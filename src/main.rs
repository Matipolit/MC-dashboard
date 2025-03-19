use std::time::Duration;

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
use serde::Deserialize;
use sha2::{
    Digest, Sha256,
    digest::{
        consts::{B0, B1},
        generic_array::GenericArray,
        typenum::{UInt, UTerm},
    },
};
use std::env;
use std::future::Future;

use tera::Tera;
use tokio::{sync::broadcast, time::Instant};
use tracing::Level;
use tracing_subscriber;

pub mod conf;

type DigestedHash =
    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>>;

#[derive(Clone)]
struct AppState {
    mc_server_broadcast: broadcast::Sender<Option<Server>>,
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

#[tokio::main]
async fn main() {
    if cfg!(debug_assertions) {
        tracing_subscriber::fmt()
            .with_max_level(Level::TRACE)
            .init();
    }
    dotenv().expect(".env file not found");

    let server_url = env::var("SERVER_URL").unwrap_or("localhost".to_string());
    let password = env::var("PASSWORD").expect("PASSWORD not set");
    let run_on_subpath_env = env::var("RUN_ON_SUBPATH");

    let run_on_subpath = run_on_subpath_env.is_ok_and(|run| run.to_lowercase() == "true");

    // Compute the hash of the password (we use this both for API and web authentication)
    let hashed_password = Sha256::digest(password);

    let server_conf = Conf::create_with_port(&server_url, 25565);

    let (server_broadcast, _) = broadcast::channel::<Option<Server>>(1);

    let templates = Tera::new("templates/**/*").expect("Error initializing Tera");

    let app_state = AppState {
        mc_server_broadcast: server_broadcast.clone(),
        server_conf: server_conf.clone(),
        templates,
        running_on_subpath: run_on_subpath,
        auth_hash: hashed_password,
    };

    tokio::task::spawn_blocking(move || {
        loop {
            let info_result: Result<Server, MspErr> = server_conf.get_server_status();
            if let Ok(info) = info_result {
                tracing::trace!("Broadcasting server info");
                let _ = server_broadcast.send(Some(info));
            }
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
            .with_state(app_state);
        Router::new().nest("/mc-dash", router)
    };

    // run it
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on {}", listener.local_addr().unwrap());
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
    State(app_state): State<AppState>,
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
        if authenticate(&app_state.auth_hash, &pass) {
            let response = handler(State(app_state)).await;
            return response.into_response();
        }
    }
    Redirect::to("/login").into_response()
}

async fn main_page_get(State(app_state): State<AppState>) -> Html<String> {
    let info_result: Result<Server, MspErr> = app_state.server_conf.get_server_status();
    if let Ok(info) = info_result {
        Html(format!("<h1>version{:?}</h1>", info.version))
    } else {
        Html("<h1>Could not get server info</h1>".into())
    }
}

async fn login_page_get(State(app_state): State<AppState>) -> Html<String> {
    Html(
        app_state
            .templates
            .render("login.html", &tera::Context::new())
            .unwrap(),
    )
}

async fn login_post(
    cookies: CookieJar,
    State(state): State<AppState>,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let redirect = if state.running_on_subpath {
        Redirect::to("/mc-dash")
    } else {
        Redirect::to("/")
    };
    if authenticate(&state.auth_hash, &form.password) {
        let cookie = Cookie::build(("auth", form.password))
            .path("/")
            // For web UI usage you may want JS to read it, so not HTTP-only.
            .http_only(false);

        let cookies = cookies.add(cookie);
        (cookies, redirect)
    } else {
        // On failed login, simply redirect back.
        (cookies, redirect)
    }
}
