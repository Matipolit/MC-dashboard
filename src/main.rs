use std::env;
use std::future::Future;
use std::process::Command;
use std::time::Duration;

use regex::Regex;

use axum::{
    Form, Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use dotenvy::dotenv;
use msp::{Conf, MspErr, Server};
use serde::{Deserialize, Serialize};
use sha2::{
    Digest, Sha256,
    digest::{
        consts::{B0, B1},
        generic_array::GenericArray,
        typenum::{UInt, UTerm},
    },
};

use tera::Tera;
use tokio::sync::broadcast;
use tracing::Level;
use tracing_subscriber;

use num_cpus;

pub mod conf;

type DigestedHash =
    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>;

#[derive(Clone)]
struct AppState {
    mc_server_broadcast: broadcast::Sender<RealTimeData>,
    server_conf: Conf,
    templates: Tera,
    running_on_subpath: bool,
    auth_hash: DigestedHash,
}

#[derive(Deserialize)]
struct PasswordQuery {
    password: Option<String>,
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

#[derive(Serialize, Clone)]
struct ServerProtocolInfo {
    version: String,
    max_players: i32,
    online_players: i32,
}

#[derive(Serialize, Clone)]
struct PerformanceInfo {
    mem_total: f32,
    mem_used: f32,
    mem_used_mc: f32,
    cpu_used: f32,
    cpu_used_mc: f32,
}

#[derive(Serialize, Clone)]
struct RealTimeData {
    protocol_info: Option<ServerProtocolInfo>,
    active: bool,
    performance_info: Option<PerformanceInfo>,
}

fn get_service_active() -> bool {
    let is_service_active_output = Command::new("systemctl")
        .args(["is-active", "--user", "minecraft"])
        .output()
        .expect("Could not get minecraft systemd service status")
        .stdout;
    let str_output =
        String::from_utf8(is_service_active_output).expect("Malformed output from systemctl");
    let trimmed_output = str_output.trim();
    let result = trimmed_output.eq("active");
    return result;
}

fn get_service_pid() -> Option<String> {
    let pid_output_res = Command::new("systemctl")
        .args(["show", "--user", "minecraft", "--property=MainPID", "value"])
        .output();

    if pid_output_res.is_ok() {
        let str_output = String::from_utf8(pid_output_res.unwrap().stdout)
            .expect("Malformed output from systemctl");
        let trimmed_output = str_output.trim().to_owned();
        let split_output: Vec<String> = trimmed_output
            .split("MainPID=")
            .map(|el| el.to_owned())
            .collect();
        let pid = split_output[1].trim().to_owned();
        Some(pid)
    } else {
        None
    }
}

fn get_performance_info(pid: String, cpus: usize) -> Option<PerformanceInfo> {
    let top_output = Command::new("top")
        .args(["-b", "-n", "1", "-p", pid.as_str()])
        .output()
        .expect("Could not get minecraft process performance info")
        .stdout;

    let str_output = String::from_utf8(top_output).expect("Malformed output from top");

    let output = str_output.trim();
    let re_mem = Regex::new(
        r"MiB Mem\s*:\s*([\d\.]+)\s+total,\s+([\d\.]+)\s+free,\s+([\d\.]+)\s+used,\s+([\d\.]+)\s+buff/cache"
    ).ok()?;

    // Regex to capture overall CPU from the "%Cpu(s):" line.
    // Example line:
    // %Cpu(s):  1.2 us,  0.0 sy,  0.0 ni, 98.8 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
    // We'll capture user, system and idle.
    let re_cpu = Regex::new(
        r"%Cpu\(s\):\s*([\d\.]+)\s+us,\s+([\d\.]+)\s+sy,\s+[\d\.]+\s+ni,\s+([\d\.]+)\s+id,",
    )
    .ok()?;

    let mem_caps = re_mem.captures(output)?;
    let cpu_caps = re_cpu.captures(output)?;

    let mem_total_mib: f32 = mem_caps.get(1)?.as_str().parse().ok()?;
    let mem_used_mib: f32 = mem_caps.get(3)?.as_str().parse().ok()?;

    let mem_total = mem_total_mib / 1024.0;
    let mem_used = mem_used_mib / 1024.0;

    // Parse CPU percentages.
    let cpu_idle: f32 = cpu_caps.get(3)?.as_str().parse().ok()?;
    let cpu_used = 100.0 - cpu_idle;

    // Now, find the minecraft (java) process line.
    // We assume it's the only line whose last token is "java".
    let mut mem_used_mc: Option<f32> = None;
    let mut cpu_percent_mc: Option<f32> = None;

    // Iterate over lines; split each into tokens.
    for line in output.lines() {
        // Skip header lines that don't have at least 12 tokens.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 12 && tokens.last()? == &"java" {
            // Expected columns for top process table:
            // [0] PID, [1] USER, [2] PR, [3] NI, [4] VIRT, [5] RES, [6] SHR,
            // [7] S, [8] %CPU, [9] %MEM, [10] TIME+, [11] COMMAND
            let res_kb: f32 = tokens[5].parse().ok()?; // RES in kB
            let proc_cpu: f32 = tokens[8].parse().ok()?; // %CPU for the process
            mem_used_mc = Some(res_kb / (1024.0 * 1024.0)); // convert kB -> GB
            cpu_percent_mc = Some(proc_cpu / (cpus as f32));
            break;
        }
    }

    // Ensure we found the java (minecraft) process info.
    let mem_used_mc = mem_used_mc?;
    let cpu_used_mc = cpu_percent_mc?;

    Some(PerformanceInfo {
        mem_total,
        mem_used,
        mem_used_mc,
        cpu_used,
        cpu_used_mc,
    })
}
fn toggle_server_service(toggle_variant: String) -> bool {
    let toggle_service_output = Command::new("systemctl")
        .arg(toggle_variant)
        .arg("--user")
        .arg("minecraft")
        .output()
        .expect("Could not toggle minecraft systemd service")
        .stdout;
    let str_output =
        String::from_utf8(toggle_service_output).expect("Malformed output from systemctl");
    let trimmed_output = str_output.trim();
    tracing::debug!("output from systemctl: {}", trimmed_output);
    let result = trimmed_output.eq("");
    return result;
}

fn redirect_to(running_on_subpath: bool, destination: String) -> Redirect {
    if running_on_subpath {
        // Remove any leading slashes
        let trimmed_dest = destination.trim_start_matches('/');
        // If the destination is empty (or was just "/"), return the subpath root.
        if trimmed_dest.is_empty() {
            Redirect::to("/mc-dash")
        } else {
            Redirect::to(&format!("/mc-dash/{}", trimmed_dest))
        }
    } else {
        Redirect::to(&destination)
    }
}

#[tokio::main]
async fn main() {
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .with_max_level(Level::DEBUG)
            .init();
    }
    dotenv().expect(".env file not found");

    let server_url = env::var("SERVER_URL").unwrap_or("localhost:3000".to_owned());
    let password = env::var("PASSWORD").expect("PASSWORD not set");
    let run_on_subpath_env = env::var("RUN_ON_SUBPATH");

    let run_on_subpath = run_on_subpath_env.is_ok_and(|run| run.to_lowercase() == "true");

    // Compute the hash of the password (we use this both for API and web authentication)
    let hashed_password = Sha256::digest(password);

    let server_conf = Conf::create_with_port("localhost", 25565);

    let (server_broadcast, _) = broadcast::channel::<RealTimeData>(1);

    let templates = Tera::new("templates/**/*").expect("Error initializing Tera");

    let app_state = AppState {
        mc_server_broadcast: server_broadcast.clone(),
        server_conf: server_conf.clone(),
        templates,
        running_on_subpath: run_on_subpath,
        auth_hash: hashed_password,
    };

    let cpus = num_cpus::get();
    tracing::debug!(
        "Detected {} cpus on this system, will divide MC cpu usage by this number.",
        cpus
    );

    tokio::task::spawn_blocking(move || {
        loop {
            let active = get_service_active();
            let server_result = server_conf.get_server_status();
            tracing::trace!("Broadcasting server info");
            let protocol_info = if server_result.is_ok() {
                let info = server_result.unwrap();
                Some(ServerProtocolInfo {
                    max_players: info.players.max,
                    online_players: info.players.online,
                    version: info.version.name,
                })
            } else {
                tracing::error!(
                    "Error while getting server protocol info: {:?}",
                    server_result
                );
                None
            };

            let performance_info: Option<PerformanceInfo> = if active {
                let pid_opt = get_service_pid();
                tracing::trace!("getting performance info for pid: {:?}", pid_opt);
                if let Some(pid) = pid_opt {
                    get_performance_info(pid, cpus)
                } else {
                    tracing::error!("Could not get PID!");
                    None
                }
            } else {
                None
            };

            let _ = server_broadcast.send(RealTimeData {
                protocol_info,
                active,
                performance_info,
            });
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let app = if !run_on_subpath {
        Router::new()
            .route(
                "/",
                get(|state, cookies, query| async {
                    auth_wrapper(state, cookies, query, main_page_get).await
                }),
            )
            .route("/login", get(login_page_get))
            .route("/login", post(login_post))
            .route("/logout", get(logout_page_get))
            .route("/realtime-stats", get(realtime_serverinfo_get))
            .route(
                "/toggle",
                get(|state, cookies, query| async {
                    auth_wrapper(state, cookies, query, toggle_server).await
                }),
            )
            .with_state(app_state)
    } else {
        let router = Router::new()
            .route(
                "/",
                get(|state, cookies, query| async {
                    auth_wrapper(state, cookies, query, main_page_get).await
                }),
            )
            .route("/login", get(login_page_get))
            .route("/login", post(login_post))
            .route("/logout", get(logout_page_get))
            .route("/realtime-stats", get(realtime_serverinfo_get))
            .route(
                "/toggle",
                get(|state, cookies, query| async {
                    auth_wrapper(state, cookies, query, toggle_server).await
                }),
            )
            .with_state(app_state);
        Router::new().nest("/mc-dash", router)
    };

    let listener = tokio::net::TcpListener::bind(server_url).await.unwrap();
    if !run_on_subpath {
        println!("listening on {}", listener.local_addr().unwrap());
    } else {
        println!("listening on {}/mc-dash", listener.local_addr().unwrap());
    }
    axum::serve(listener, app).await.unwrap();
}

async fn realtime_serverinfo_get(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|ws: WebSocket| async { realtime_serverinfo_stream(state, ws).await })
}

async fn realtime_serverinfo_stream(app_state: AppState, mut ws: WebSocket) {
    let mut rx = app_state.mc_server_broadcast.subscribe();

    while let Ok(msg) = rx.recv().await {
        ws.send(Message::text(serde_json::to_string(&msg).unwrap()))
            .await
            .unwrap();
    }
}
fn authenticate(original_hash: &DigestedHash, provided_pass: &String) -> bool {
    if Sha256::digest(provided_pass).eq(original_hash) {
        return true;
    } else {
        return false;
    }
}

/// Helper for API endpoints: extract a provided password from either the query or a cookie.
fn extract_provided(query: &PasswordQuery, cookies: &CookieJar) -> Option<String> {
    query
        .password
        .as_ref()
        .and_then(|p| Some(p.clone()))
        .or_else(|| cookies.get("auth").map(|c| c.value().to_owned()))
}

async fn auth_wrapper<F, Fut, R>(
    State(state): State<AppState>,
    cookies: CookieJar,
    query: Query<PasswordQuery>,
    handler: F,
) -> impl IntoResponse
where
    F: FnOnce(State<AppState>) -> Fut,
    Fut: Future<Output = R>,
    R: IntoResponse,
{
    if let Some(pass) = extract_provided(&query.0, &cookies) {
        if authenticate(&state.auth_hash, &pass) {
            let response = handler(State(state)).await;
            tracing::debug!("user authenticated, returing desired response");
            return response.into_response();
        }
    }
    tracing::debug!("user not authenticated, redirecting to login");

    redirect_to(state.running_on_subpath, "login".to_owned()).into_response()
}

async fn main_page_get(State(state): State<AppState>) -> Html<String> {
    let active = get_service_active();
    let mut context = tera::Context::new();
    context.insert("active", &active);
    context.insert("subpath", &state.running_on_subpath);
    Html(state.templates.render("index.html", &context).unwrap())
}

async fn login_page_get(State(app_state): State<AppState>) -> Html<String> {
    Html(
        app_state
            .templates
            .render("login.html", &tera::Context::new())
            .unwrap(),
    )
}

async fn logout_page_get(State(state): State<AppState>, cookies: CookieJar) -> impl IntoResponse {
    let cookies = cookies.remove(Cookie::from("auth"));
    let redirect = redirect_to(state.running_on_subpath, "/login".to_owned());
    (cookies, redirect)
}

async fn toggle_server(State(state): State<AppState>) -> impl IntoResponse {
    let active = get_service_active();
    let toggle_res = if active {
        toggle_server_service("stop".into());
    } else {
        toggle_server_service("start".into());
    };

    redirect_to(state.running_on_subpath, "/".to_owned())
}

async fn login_post(
    cookies: CookieJar,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    tracing::debug!("login post form received");
    let redirect = redirect_to(state.running_on_subpath, "/".to_owned());
    if authenticate(&state.auth_hash, &form.password) {
        tracing::info!("Authentication successful!");
        let cookie = Cookie::build(("auth", form.password))
            .path("/")
            // For web UI usage you may want JS to read it, so not HTTP-only.
            .http_only(false);

        let cookies = cookies.add(cookie);
        (cookies, redirect)
    } else {
        tracing::info!("Authentication unsuccessful!");
        // On failed login, simply redirect back.
        (cookies, redirect)
    }
}
