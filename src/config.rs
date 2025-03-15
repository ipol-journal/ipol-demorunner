use rocket::serde::Deserialize;

use crate::model::RunParams;

#[derive(Deserialize, Debug)]
pub struct Config {
    pub compilation_root: String,
    pub docker_image_prefix: String,
    pub docker_exec_prefix: String,
    pub exec_workdir_in_docker: String,
    pub user_uid_gid: String,
    #[serde(default = "five_minutes")]
    pub max_timeout: u64,
    pub gpus: Vec<String>,
    #[serde(default)]
    pub env_vars: RunParams,
    pub registry_url: Option<String>,
}

const fn five_minutes() -> u64 {
    5 * 60
}

pub fn load_rocket_config() -> rocket::fairing::AdHoc {
    rocket::fairing::AdHoc::config::<Config>()
}
