use rocket::serde::json::Json;
use rocket::serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ShutdownResponse {
    status: String,
}

#[get("/shutdown")]
pub fn shutdown(shutdown: rocket::Shutdown) -> Json<ShutdownResponse> {
    shutdown.notify();
    Json(ShutdownResponse {
        status: "OK".into(),
    })
}
