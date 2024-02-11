use rocket::{Build, Rocket};
use tracing_subscriber::EnvFilter;

#[macro_use]
extern crate rocket;

mod compilation;
mod config;
mod execution;
mod model;
mod ping;
mod shutdown;
mod workload;

#[get("/")]
const fn index() -> &'static str {
    "This is the IPOL DemoRunner module (docker)"
}

fn main_rocket() -> Rocket<Build> {
    rocket::build()
        .mount(
            "/",
            routes![
                index,
                ping::http::ping,
                shutdown::shutdown,
                workload::get_workload,
                compilation::ensure_compilation,
                execution::http::exec_and_wait
            ],
        )
        .attach(config::load_rocket_config())
}

#[launch]
fn _main() -> _ {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(env_filter)
        .init();
    main_rocket()
}

#[cfg(test)]
mod test {
    // TODO: remove git repositories and docker images
    pub const GIT_URL: &str = "https://github.com/kidanger/ipol-demo-zero";
}
