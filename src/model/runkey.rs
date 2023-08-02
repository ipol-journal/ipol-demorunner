use regex::Regex;
use rocket::{
    form::{FromFormField, ValueField},
    http::uri::fmt::UriDisplay,
    request::FromParam,
};
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunKey(String);

impl Display for RunKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<String> for RunKey {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl TryFrom<&str> for RunKey {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        lazy_static::lazy_static! {
        static ref RE: Regex = Regex::new(r"^\w+$").unwrap();
        }
        if !RE.is_match(s) {
            return Err("invalid key");
        }
        Ok(RunKey(s.to_string()))
    }
}

impl<'a> FromParam<'a> for RunKey {
    type Error = &'a str;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        param.try_into()
    }
}

impl rocket::http::uri::fmt::FromUriParam<rocket::http::uri::fmt::Path, &RunKey> for RunKey {
    type Target = RunKey;

    fn from_uri_param(param: &RunKey) -> Self::Target {
        param.clone()
    }
}

impl rocket::http::uri::fmt::FromUriParam<rocket::http::uri::fmt::Query, &RunKey> for RunKey {
    type Target = RunKey;

    fn from_uri_param(param: &RunKey) -> Self::Target {
        param.clone()
    }
}

impl<P: rocket::http::uri::fmt::Part> UriDisplay<P> for RunKey {
    fn fmt(&self, f: &mut rocket::http::uri::fmt::Formatter<'_, P>) -> std::fmt::Result {
        f.write_value(self.as_ref())
    }
}

#[rocket::async_trait]
impl<'r> FromFormField<'r> for RunKey {
    fn from_value(field: ValueField<'r>) -> rocket::form::Result<'r, Self> {
        Self::try_from(field.value).map_err(|e| rocket::form::Error::validation(e).into())
    }
}
