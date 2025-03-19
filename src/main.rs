use std::time::Duration;

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::{Html, IntoResponse},
    routing::get,
};
use msp::{Conf, MspErr, Server};
use tokio::{sync::broadcast, time::Instant};

pub mod conf;

#[derive(Clone)]
struct AppState {
    mc_server_broadcast: broadcast::Sender<Option<Server>>,
    server_conf: Conf,
}

#[tokio::main]
async fn main() {
    let server_conf = Conf::create_with_port("91.99.30.82", 25565);

    let (server_broadcast, _) = broadcast::channel::<Option<Server>>(1);

    let app_state = AppState {
        mc_server_broadcast: server_broadcast.clone(),
        server_conf: server_conf.clone(),
    };

    tokio::task::spawn_blocking(move || {
        loop {
            let info_result: Result<Server, MspErr> = server_conf.get_server_status();
            if let Ok(info) = info_result {
                println!("Got new server info");
                let _ = server_broadcast.send(Some(info));
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    });

    let app = Router::new()
        .route("/", get(main_page_get))
        .with_state(app_state);

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

async fn main_page_get(State(app_state): State<AppState>) -> Html<String> {
    let info_result: Result<Server, MspErr> = app_state.server_conf.get_server_status();
    if let Ok(info) = info_result {
        Html(format!("<h1>version{:?}</h1>", info.version))
    } else {
        Html("<h1>Could not get server info</h1>".into())
    }
}
