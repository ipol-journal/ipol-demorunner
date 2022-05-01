use rocket::serde::json::Json;
use rocket::serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PingResponse {
    status: String,
    ping: String,
}

#[get("/ping")]
pub fn ping() -> Json<PingResponse> {
    Json(PingResponse {
        status: "OK".into(),
        ping: "pong".into(),
    })
}
