use rocket::serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod demoid;
mod runkey;

pub use demoid::DemoID;
pub use runkey::RunKey;

pub type DDLRun = String;
pub type RunParams = HashMap<String, ParamValue>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DDLBuild {
    pub url: String,
    pub ssh_fingerprint: Option<String>,
    pub rev: String,
    pub dockerfile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ParamValue {
    Bool(bool),
    PosInt(u64),
    NegInt(i64),
    Float(f64),
    String(String),
}

impl std::fmt::Display for ParamValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamValue::Bool(v) => write!(f, "{}", v),
            ParamValue::PosInt(v) => write!(f, "{}", v),
            ParamValue::NegInt(v) => write!(f, "{}", v),
            ParamValue::Float(v) => write!(f, "{}", v),
            ParamValue::String(v) => write!(f, "{}", v),
        }
    }
}

pub trait ToEnvVec {
    fn is_valid_param_name(name: &str) -> bool {
        const INVALID_NAMES: &[&str] = &[
            "HOSTNAME",
            "PATH",
            "HOME",
            "LANG",
            "TERM",
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "PYTHONPATH",
            "PERLLIB",
            "RUBYLIB",
            "CLASSPATH",
            "NODE_PATH",
            "IPOL_DEMOID",
            "IPOL_KEY",
        ];
        !INVALID_NAMES.contains(&name) && !name.contains('=')
    }

    fn to_env_vec(&self, demo_id: &DemoID, key: &RunKey) -> Vec<String>;
}

impl ToEnvVec for RunParams {
    fn to_env_vec(&self, demo_id: &DemoID, key: &RunKey) -> Vec<String> {
        let mut env = vec![
            format!("IPOL_DEMOID={}", demo_id),
            format!("IPOL_KEY={}", key),
        ];
        for (name, value) in self
            .iter()
            .filter(|(name, _)| Self::is_valid_param_name(name))
        {
            env.push(format!("{}={}", name, value));
        }
        env
    }
}
