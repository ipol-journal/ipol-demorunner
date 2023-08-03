use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;

#[get("/workload")]
pub fn get_workload() -> status::Custom<Json<f32>> {
    status::Custom(Status::Ok, Json(1.0))
}

#[cfg(test)]
mod test {
    use crate::main_rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    #[test]
    #[tracing_test::traced_test]
    fn test_get_workfload() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let response = client.get("/workload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.into_json(), Some(1.0));
    }
}
