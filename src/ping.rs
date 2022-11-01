use rocket::serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PingResponse {
    status: String,
    ping: String,
}

pub mod http {
    use rocket::serde::json::Json;

    use crate::ping::PingResponse;

    #[get("/ping")]
    pub fn ping() -> Json<PingResponse> {
        Json(PingResponse {
            status: "OK".into(),
            ping: "pong".into(),
        })
    }
}
