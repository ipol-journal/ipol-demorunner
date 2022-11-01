use once_cell::sync::Lazy;
use rocket::{Build, Rocket};
use tracing_subscriber::EnvFilter;

#[macro_use]
extern crate rocket;

pub mod compilation;
pub mod config;
pub mod execution;
pub mod model;
pub mod ping;
pub mod shutdown;
pub mod workload;

#[get("/")]
const fn index() -> &'static str {
    "This is the IPOL DemoRunner module (docker)"
}

static TRACING: Lazy<()> = Lazy::new(|| {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or(EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_env_filter(env_filter)
        .init();
});

fn main_rocket() -> Rocket<Build> {
    rocket::build()
        .mount(
            "/",
            routes![
                index,
                ping::ping,
                shutdown::shutdown,
                workload::get_workload,
                compilation::ensure_compilation,
                execution::exec_and_wait
            ],
        )
        .attach(config::load_rocket_config())
}

#[launch]
fn _main() -> _ {
    Lazy::force(&TRACING);
    main_rocket()
}

#[cfg(test)]
mod test {
    // TODO: remove git repositories and docker images
    pub const GIT_URL: &str = "https://github.com/kidanger/ipol-demo-zero";
}
