use std::env;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;
use headers::{Authorization, HeaderMapExt, authorization::Bearer};
use jsonwebtoken::{DecodingKey, Header as JwtHeader, Validation, decode};
use regex::Regex;

use axum::{
    Json, Router,
    extract::{
        Query, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use dotenvy::dotenv;
use msp::Conf;
use serde::{Deserialize, Serialize};
use sha2::{
    Digest, Sha256,
    digest::{
        consts::{B0, B1},
        generic_array::GenericArray,
        typenum::{UInt, UTerm},
    },
};

use tokio::sync::broadcast;
use tracing::Level;
use tracing_subscriber;

use num_cpus;

// --- Custom API Error ---

enum ApiError {
    Unauthorized,
    InternalServerError(String),
    BadRequest(String),
    ServiceUnavailable(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::ServiceUnavailable(msg) => (StatusCode::SERVICE_UNAVAILABLE, msg),
        };
        let body = Json(error_message);
        (status, body).into_response()
    }
}

type DigestedHash =
    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>;

// --- JWT Claims ---

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // Subject (username)
    exp: usize,  // Expiration time (seconds since epoch)
}

#[derive(Clone)]
struct AppState {
    mc_server_broadcast: broadcast::Sender<RealTimeData>,
    server_conf: Conf,
    running_on_subpath: bool,
    auth_username: String,
    auth_hash: DigestedHash,
    jwt_secret: String,
}

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Serialize)]
struct ServerToggleResponse {
    running: bool,
}

#[derive(Serialize, Clone, Debug)]
struct PerformanceInfo {
    mem_total: f32,
    mem_used: f32,
    mem_used_mc: f32,
    cpu_used: f32,
    cpu_used_mc: f32,
}

#[derive(Serialize, Clone)]
struct RealTimeData {
    version: Option<String>,
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
    tracing::trace!("top output: {:?}", output);
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

    tracing::debug!("got some regex captures");

    let mem_total_mib: f32 = mem_caps.get(1)?.as_str().parse().ok()?;
    let mem_used_mib: f32 = mem_caps.get(3)?.as_str().parse().ok()?;

    let mem_total = mem_total_mib / 1024.0;
    let mem_used = mem_used_mib / 1024.0;

    tracing::debug!("parsed memory: total - {}, used - {}", mem_total, mem_used);

    // Parse CPU percentages.
    let cpu_idle: f32 = cpu_caps.get(3)?.as_str().parse().ok()?;
    let cpu_used = 100.0 - cpu_idle;

    tracing::debug!("parsed cpu: used - {}", cpu_used);

    // Now, find the minecraft (java) process line.
    // We assume it's the only line whose last token is "java".
    let mut mem_used_mc: Option<f32> = None;
    let mut cpu_percent_mc: Option<f32> = None;

    // Iterate over lines; split each into tokens.
    for line in output.lines() {
        // Skip header lines that don't have at least 12 tokens.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 12 && tokens.last()? == &"java" {
            tracing::debug!("got the desired tokens: {:?}", tokens);
            // Expected columns for top process table:
            // [0] PID, [1] USER, [2] PR, [3] NI, [4] VIRT, [5] RES, [6] SHR,
            // [7] S, [8] %CPU, [9] %MEM, [10] TIME+, [11] COMMAND
            if tokens[5].ends_with("g") {
                let mem_stripped = tokens[5].strip_suffix("g");
                if let Some(mem) = mem_stripped {
                    let res_gb: f32 = mem.parse().ok()?;
                    mem_used_mc = Some(res_gb);
                }
            } else if tokens[5].ends_with("m") {
                let mem_stripped = tokens[5].strip_suffix("m");
                if let Some(mem) = mem_stripped {
                    let res_mb: f32 = mem.parse().ok()?;
                    mem_used_mc = Some(res_mb / 1024.0);
                }
            } else {
                let res_kb: f32 = tokens[5].parse().ok()?; // RES in kB
                mem_used_mc = Some(res_kb / (1024.0 * 1024.0)); // convert kB -> GB
            }
            let proc_cpu: f32 = tokens[8].parse().ok()?; // %CPU for the process
            cpu_percent_mc = Some(proc_cpu / (cpus as f32));
            tracing::debug!(
                "got mc info: mem - {:?}, cpu - {:?}",
                mem_used_mc,
                cpu_percent_mc
            );
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

fn get_realtime_data(
    server_version: &mut Option<String>,
    server_conf: &Conf,
    cpus: usize,
) -> RealTimeData {
    let active = get_service_active();
    if !active {
        *server_version = None;
    }
    if active && server_version.is_none() {
        let server_result = server_conf.get_server_status();
        if let Ok(result) = server_result {
            *server_version = Some(result.version.name);
        }
        tracing::debug!("New server version set: {:?}", server_version);
    }
    tracing::trace!("Broadcasting server info");

    let performance_info: Option<PerformanceInfo> = if active {
        let pid_opt = get_service_pid();
        tracing::trace!("getting performance info for pid: {:?}", pid_opt);
        if let Some(pid) = pid_opt {
            let info = get_performance_info(pid, cpus);
            tracing::debug!("Performance info: {:?}", info);
            info
        } else {
            tracing::error!("Could not get PID!");
            None
        }
    } else {
        None
    };

    return (RealTimeData {
        active,
        performance_info,
        version: server_version.clone(),
    });
}

#[tokio::main]
async fn main() {
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .init();
    }
    dotenv().expect(".env file not found");

    let server_url = env::var("SERVER_URL").unwrap_or("localhost:3000".to_owned());
    let username = env::var("USERNAME").expect("USERNAME not set");
    let password = env::var("PASSWORD").expect("PASSWORD not set");
    let run_on_subpath_env = env::var("RUN_ON_SUBPATH");
    let jwt_secret = env::var("JWT_SECRET").expect("JWT secret not provided!");

    let run_on_subpath = run_on_subpath_env.is_ok_and(|run| run.to_lowercase() == "true");

    // Compute the hash of the password (we use this both for API and web authentication)
    let hashed_password = Sha256::digest(password);

    let server_conf = Conf::create_with_port("localhost", 25565);

    let (server_broadcast, _) = broadcast::channel::<RealTimeData>(1);

    let app_state = AppState {
        mc_server_broadcast: server_broadcast.clone(),
        server_conf: server_conf.clone(),
        running_on_subpath: run_on_subpath,
        auth_username: username,
        auth_hash: hashed_password,
        jwt_secret,
    };

    let cpus = num_cpus::get();
    tracing::debug!(
        "Detected {} cpus on this system, will divide MC cpu usage by this number.",
        cpus
    );

    let mut server_version: Option<String> = None;

    tokio::task::spawn_blocking(move || {
        loop {
            let _ =
                server_broadcast.send(get_realtime_data(&mut server_version, &server_conf, cpus));
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let unprotected_api_routes = Router::new().route("/auth/login", post(login_handler)); // Login doesn't need auth middleware

    let protected_api_routes = Router::new()
        .route("/", get(main_page_handler))
        .route("/server/toggle", post(toggle_server_handler))
        .route("/realtime-stats", get(realtime_serverinfo_get))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    let api_router = Router::new()
        .merge(unprotected_api_routes)
        .merge(protected_api_routes);

    // --- Conditionally Nest Routes ---
    let app = if run_on_subpath {
        Router::new()
            .nest(
                "/mc-dash",
                Router::new().nest("/api", api_router), //double nesting
            )
            .with_state(app_state)
        //.layer(cors)
    } else {
        Router::new().nest("/api", api_router).with_state(app_state)
        //.layer(cors)
    };

    let listener = tokio::net::TcpListener::bind(server_url).await.unwrap();
    if !run_on_subpath {
        tracing::info!("listening on {}", listener.local_addr().unwrap());
    } else {
        tracing::info!("listening on {}/mc-dash", listener.local_addr().unwrap());
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
    tracing::info!("WebSocket client connected for real-time stats");
    while let Ok(msg) = rx.recv().await {
        if ws
            .send(Message::text(serde_json::to_string(&msg).unwrap_or_else(
                |e| {
                    tracing::error!("Failed to serialize RealTimeData: {}", e);
                    "{\"error\":\"serialization failed\"}".to_string()
                },
            )))
            .await
            .is_err()
        {
            tracing::info!("WebSocket client disconnected");
            break;
        }
    }
}

// helper
fn authenticate(app_state: &AppState, provided_pass: &String, provided_username: &String) -> bool {
    if Sha256::digest(provided_pass).eq(&app_state.auth_hash)
        && provided_username.eq(&app_state.auth_username)
    {
        return true;
    } else {
        return false;
    }
}

// GET /api
async fn main_page_handler() -> Json<String> {
    Json("Welcome to MC server api!".to_owned())
}

// POST /api/server/toggle
async fn toggle_server_handler(State(state): State<AppState>) -> impl IntoResponse {
    let active = get_service_active();
    let toggle_res = if active {
        toggle_server_service("stop".into())
    } else {
        toggle_server_service("start".into())
    };
    Json(ServerToggleResponse { running: !active })
}

// POST /api/auth/login
async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    tracing::debug!("login request received");
    if authenticate(&state, &payload.password, &payload.username) {
        tracing::info!("Authentication successful!");
        // --- Password is valid, generate JWT ---
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(2592000); // 1 month

        let claims = Claims {
            sub: payload.username.clone(),
            exp: expires_at.timestamp() as usize,
        };

        let token = jsonwebtoken::encode(
            &JwtHeader::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(state.jwt_secret.as_ref()),
        )
        .map_err(|e| ApiError::InternalServerError(format!("Failed to create token: {}", e)))?;

        Ok(Json(LoginResponse { token }))
    } else {
        tracing::info!("Authentication unsuccessful!");
        return Err(ApiError::Unauthorized);
    }
}

async fn auth_middleware(
    State(state): State<AppState>,
    query: Query<TokenQuery>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = request.headers().typed_get::<Authorization<Bearer>>();

    let token = match auth_header {
        Some(Authorization(bearer)) => bearer.token().to_string(),
        None => {
            tracing::debug!("Auth middleware: Missing Authorization header, trying query param");
            match &query.token {
                Some(token) => token.clone(),
                None => {
                    tracing::debug!("Auth middleware: Not found in query param");
                    return Err(StatusCode::UNAUTHORIZED);
                }
            }
        }
    };

    let decoding_key = DecodingKey::from_secret(state.jwt_secret.as_ref());
    let validation = Validation::default();

    match decode::<Claims>(&token, &decoding_key, &validation) {
        Ok(token_data) => {
            tracing::trace!(
                "Auth middleware: Token validated successfully for user: {}",
                token_data.claims.sub
            );
            // Note: Inserting claims into extensions is harder with from_fn_with_state middleware.
            // If handlers need the claims, consider a custom middleware struct or passing state differently.
            // For now, we just validate and proceed.
            Ok(next.run(request).await)
        }
        Err(e) => {
            tracing::debug!("Auth middleware: Invalid token: {}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
