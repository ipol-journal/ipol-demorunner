use regex::Regex;
use rocket::{http::uri::fmt::UriDisplay, request::FromParam};
use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct DemoID(String);

impl Display for DemoID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<String> for DemoID {
    fn as_ref(&self) -> &String {
        &self.0
    }
}

impl TryFrom<&str> for DemoID {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        lazy_static::lazy_static! {
            static ref RE: Regex = Regex::new(r"^\w+$").unwrap();
        }
        if !RE.is_match(s) {
            return Err("invalid demo_id");
        }
        Ok(DemoID(s.to_string()))
    }
}

impl<'a> FromParam<'a> for DemoID {
    type Error = &'a str;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        param.try_into()
    }
}

impl rocket::http::uri::fmt::FromUriParam<rocket::http::uri::fmt::Path, &DemoID> for DemoID {
    type Target = DemoID;

    fn from_uri_param(param: &DemoID) -> Self::Target {
        param.clone()
    }
}

impl<P: rocket::http::uri::fmt::Part> UriDisplay<P> for DemoID {
    fn fmt(&self, f: &mut rocket::http::uri::fmt::Formatter<'_, P>) -> std::fmt::Result {
        f.write_value(self.as_ref())
    }
}
