use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[macro_use]
extern crate rocket;
use rocket::fairing::AdHoc;
use rocket::form::{self, Form};
use rocket::http::hyper::Body;
use rocket::serde::json::{Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::fs;
use rocket::tokio::io::AsyncWriteExt;
use rocket::tokio::time::error::Elapsed;
use rocket::tokio::time::{timeout_at, Instant};
use rocket::{tokio, State};

#[macro_use(defer)]
extern crate scopeguard;
use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, LogOutput, LogsOptions,
    RemoveContainerOptions,
};
use bollard::{image::BuildImageOptions, Docker};
use lazy_static::lazy_static;
use regex::Regex;

use futures_util::stream::StreamExt;
use git2::Repository;
use tar::Builder;

#[derive(Deserialize)]
struct RunnerConfig {
    execution_root: String,
    compilation_root: String,
    docker_image_prefix: String,
    docker_exec_prefix: String,
    exec_workdir_in_docker: String,
    user_uid_gid: String,
}

type DemoID = String;

fn validate_demoid<'v>(s: &str) -> form::Result<'v, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^\w+$").unwrap();
    }
    if !RE.is_match(s) {
        return Err(rocket::form::Error::validation("invalid demo_id").into());
    }
    Ok(())
}

type RunKey = String;

fn validate_runkey<'v>(s: &str) -> form::Result<'v, ()> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r"^\w+$").unwrap();
    }
    if !RE.is_match(s) {
        return Err(rocket::form::Error::validation("invalid key").into());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
enum ParamValue {
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

type RunParams = HashMap<String, ParamValue>;

type DDLRun = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DDLBuild {
    url: String,
    rev: String,
    dockerfile: String,
}

#[derive(Debug, Serialize)]
struct PingResponse {
    status: String,
    ping: String,
}

#[get("/ping")]
fn ping() -> Json<PingResponse> {
    Json(PingResponse {
        status: "OK".into(),
        ping: "pong".into(),
    })
}

#[derive(Debug, Serialize)]
struct ShutdownResponse {
    status: String,
}

#[get("/shutdown")]
fn shutdown(shutdown: rocket::Shutdown) -> Json<ShutdownResponse> {
    shutdown.notify();
    Json(ShutdownResponse {
        status: "OK".into(),
    })
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Workload {
    status: String,
    workload: f32,
}

#[get("/get_workload")]
fn get_workload() -> Json<Workload> {
    Json(Workload {
        status: "OK".into(),
        workload: 1.0,
    })
}

#[derive(Debug, Serialize)]
struct Stats {
    status: String,
    demo_id: DemoID,
    key: RunKey,
    date: String,
}

#[get("/get_stats")]
fn get_stats() -> Json<Stats> {
    todo!();
}

#[derive(Debug, FromForm)]
struct EnsureCompilationRequest {
    #[field(validate=validate_demoid())]
    demo_id: DemoID,
    ddl_build: Json<DDLBuild>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnsureCompilationResponse {
    status: String,
    message: String,
}

#[derive(Debug, thiserror::Error)]
enum CompilationError {
    #[error("Compilation error: {0}")]
    BuildError(String),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("{0}")]
    Git(#[from] git2::Error),
    #[error("Couldn't find dockerfile: {0}")]
    MissingDockerfile(String),
}

fn url_of_git_repository(srcdir: &Path) -> Option<String> {
    let repo = Repository::open(srcdir).ok()?;
    let remote = repo.find_remote("origin").ok()?;
    let url = remote.url()?;
    Some(String::from(url))
}

fn prepare_git(path: &Path, url: &str, rev: &str) -> Result<(), CompilationError> {
    if let Some(current_url) = url_of_git_repository(path) {
        if current_url != url {
            std::fs::remove_dir_all(path)?;
        }
    } else if path.exists() {
        std::fs::remove_dir_all(path)?;
    }

    let repo = if !path.exists() {
        // TODO: credentials
        // TODO: shallow clone
        Repository::clone_recurse(url, path)?
    } else {
        Repository::open(path)?
    };

    {
        let mut remote = repo.find_remote("origin")?;
        // TODO: shallow fetch the rev
        remote.fetch(&["master"], None, None)?;
    }

    {
        // TODO: support "master" as rev instead of "origin/master"
        let object = repo.revparse_single(rev)?;
        dbg!(object.clone());
        repo.checkout_tree(&object, None)?;
        repo.set_head_detached(object.id())?;
    }
    Ok(())
}

async fn ensure_compilation_inner(
    req: Form<EnsureCompilationRequest>,
    config: &State<RunnerConfig>,
) -> Result<(), CompilationError> {
    dbg!(&req);

    let compilation_path = PathBuf::from(&config.compilation_root).join(&req.demo_id);
    let srcdir = PathBuf::from(&compilation_path).join("src");
    let logfile = PathBuf::from(&compilation_path).join("build.log");
    fs::create_dir_all(&compilation_path).await?;
    let mut buildlog = fs::File::create(logfile).await?;

    // TODO: detect if we actually need to recompile

    {
        let srcdir = srcdir.clone();
        let ddl_build = req.ddl_build.clone();
        tokio::task::spawn_blocking(move || prepare_git(&srcdir, &ddl_build.url, &ddl_build.rev))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))??;
    }

    if !PathBuf::from(&srcdir)
        .join(&req.ddl_build.dockerfile)
        .exists()
    {
        return Err(CompilationError::MissingDockerfile(
            req.ddl_build.dockerfile.clone(),
        ));
    }

    let vec = {
        let srcdir = srcdir.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, CompilationError> {
            let mut ar = Builder::new(Vec::new());
            // TODO: exclude .git
            ar.append_dir_all(".", srcdir)?;
            Ok(ar.into_inner()?)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))??
    };
    let tar = Body::from(vec);

    let docker = Docker::connect_with_socket_defaults()?;
    let image_name = format!("{}{}", config.docker_image_prefix, req.demo_id);
    let build_image_options = BuildImageOptions {
        dockerfile: req.ddl_build.dockerfile.as_str(),
        t: &image_name,
        q: false,
        ..Default::default()
    };
    let mut image_build_stream = docker.build_image(build_image_options, None, Some(tar));

    let mut compilation_error = None;
    while let Some(msg) = image_build_stream.next().await {
        if let Ok(info) = msg {
            if let Some(stream) = info.stream {
                buildlog.write_all(stream.as_bytes()).await?;
            }
            if let Some(err) = info.error {
                buildlog.write_all(err.as_bytes()).await?;
                compilation_error = Some(err);
            }
        }
    }

    if let Some(err) = compilation_error {
        Err(CompilationError::BuildError(err))
    } else {
        Ok(())
    }
}

#[post("/ensure_compilation", data = "<req>")]
async fn ensure_compilation(
    req: Form<EnsureCompilationRequest>,
    config: &State<RunnerConfig>,
) -> Json<EnsureCompilationResponse> {
    let response = match ensure_compilation_inner(req, config).await {
        Ok(()) => EnsureCompilationResponse {
            status: "OK".into(),
            message: String::new(),
        },
        Err(err) => EnsureCompilationResponse {
            status: "KO".into(),
            message: err.to_string(),
        },
    };
    Json(response)
}

#[derive(Debug, Deserialize)]
struct TestCompilationRequest {
    _ddl_build: DDLBuild,
    _compilation_path: String,
}

#[post("/test_compilation", data = "<_req>")]
fn test_compilation(_req: Json<TestCompilationRequest>) -> Value {
    todo!();
}

#[derive(Debug, Deserialize)]
struct DeleteCompilationRequest {
    _demo_id: DemoID,
}

#[post("/delete_compilation", data = "<_req>")]
fn delete_compilation(_req: Json<DeleteCompilationRequest>) {
    todo!();
}

#[derive(Debug, FromForm)]
struct ExecAndWaitRequest {
    #[field(validate=validate_demoid())]
    demo_id: DemoID,
    #[field(validate=validate_runkey())]
    key: RunKey,
    params: Json<RunParams>,
    ddl_run: Json<DDLRun>,
    timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ExecAndWaitResponse {
    status: String,
    message: String,
}

#[derive(Debug, thiserror::Error)]
enum ExecError {
    #[error("Non-zero exit code ({0})")]
    NonZeroExitCode(i64),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("Execution timeout")]
    Timeout(#[from] Elapsed),
}

async fn exec_and_wait_inner(
    req: Form<ExecAndWaitRequest>,
    config: &State<RunnerConfig>,
) -> Result<(), ExecError> {
    dbg!(&req);

    let outdir = PathBuf::from(&config.execution_root)
        .join(&req.demo_id)
        .join(&req.key);
    fs::create_dir_all(&outdir).await?;
    let outdir = fs::canonicalize(outdir).await?;

    let image_name = format!("{}{}:latest", config.docker_image_prefix, req.demo_id);
    let exec_mountpoint = &config.exec_workdir_in_docker;

    let mut stderr = fs::File::create(outdir.join("stderr.txt")).await?;
    let mut stdout = fs::File::create(outdir.join("stdout.txt")).await?;

    let host_config = bollard::models::HostConfig {
        binds: Some(vec![format!(
            "{}:{}",
            outdir.clone().into_os_string().into_string().unwrap(),
            exec_mountpoint,
        )]),
        ..Default::default()
    };

    let name = format!("{}{}-{}", config.docker_exec_prefix, req.demo_id, req.key);
    let options = Some(CreateContainerOptions {
        name: name.as_str(),
    });
    let mut env = vec![
        format!("IPOL_DEMOID={}", req.demo_id),
        format!("IPOL_KEY={}", req.key),
    ];
    for (name, value) in req.params.clone() {
        env.push(format!("{}={}", name, value));
    }
    let env = env.iter().map(|s| s as &str).collect();
    let config = Config {
        image: Some(image_name.as_str()),
        user: Some(&config.user_uid_gid),
        cmd: Some(vec!["/bin/bash", "-c", req.ddl_run.as_str()]),
        env: Some(env),
        working_dir: Some(exec_mountpoint),
        host_config: Some(host_config),
        ..Default::default()
    };

    let docker = Docker::connect_with_socket_defaults()?;
    let id = docker.create_container(options, config).await?.id;
    dbg!(&id);

    defer! {
        let docker = docker.clone();
        let name = name.clone();
        rocket::tokio::spawn(async move {
            let options = Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            });
            if let Err(e) = docker.remove_container(&name, options).await {
                error!("{}", e);
            }
        });
    }

    docker.start_container::<String>(&id, None).await?;

    let deadline = Instant::now() + Duration::from_secs(req.timeout);
    timeout_at(deadline, async {
        let options = Some(LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            ..Default::default()
        });
        let mut logs = docker.logs(&id, options);
        while let Some(msg) = logs.next().await {
            match msg {
                Ok(LogOutput::StdOut { message }) => {
                    println!("stdout: {message:#?}");
                    stdout.write_all(&message).await?;
                }
                Ok(LogOutput::StdErr { message }) => {
                    println!("stderr: {message:#?}");
                    stderr.write_all(&message).await?;
                }
                Ok(LogOutput::StdIn { message }) => {
                    println!("stdin: {message:#?}");
                }
                Ok(LogOutput::Console { message }) => {
                    println!("console: {message:#?}");
                }
                Err(e) => {
                    dbg!(&e);
                }
            };
        }
        Ok::<(), ExecError>(())
    })
    .await??;

    let options = Some(InspectContainerOptions { size: false });
    let inspect_response = docker.inspect_container(&name, options).await?;

    if let Some(exit_code) = (move || inspect_response.state?.exit_code)() {
        if exit_code != 0 {
            return Err(ExecError::NonZeroExitCode(exit_code));
        }
    }

    Ok(())
}

#[post("/exec_and_wait", data = "<req>")]
async fn exec_and_wait(
    req: Form<ExecAndWaitRequest>,
    config: &State<RunnerConfig>,
) -> Json<ExecAndWaitResponse> {
    let response = match exec_and_wait_inner(req, config).await {
        Ok(()) => ExecAndWaitResponse {
            status: "OK".into(),
            message: String::new(),
        },
        Err(err) => ExecAndWaitResponse {
            status: "KO".into(),
            message: err.to_string(),
        },
    };
    Json(response)
}

#[get("/")]
fn index() -> &'static str {
    "This is the IPOL DemoRunner module (docker)"
}

#[launch]
fn rocket() -> _ {
    // TODO: restrict access to the service somehow
    rocket::build()
        .mount(
            "/api/demorunner/",
            routes![
                index,
                ping,
                shutdown,
                get_workload,
                get_stats,
                ensure_compilation,
                test_compilation,
                delete_compilation,
                exec_and_wait
            ],
        )
        .mount(
            "/api/demorunner-docker/",
            routes![
                index,
                ping,
                shutdown,
                get_workload,
                get_stats,
                ensure_compilation,
                test_compilation,
                delete_compilation,
                exec_and_wait
            ],
        )
        .attach(AdHoc::config::<RunnerConfig>())
}

#[cfg(test)]
mod test {
    use super::rocket;
    use super::*;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    // TODO: remove git repositories and docker images

    #[test]
    fn test_get_workfload() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/api/demorunner/get_workload").dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(Workload {
                status: "OK".into(),
                workload: 1.0,
            })
        );
    }

    #[test]
    fn test_ensure_compilation() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: "https://github.com/kidanger/ipol-demo-zero".into(),
            rev: "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79".into(),
            dockerfile: ".ipol/Dockerfile".into(),
        };
        let response = client
            .post("/api/demorunner/ensure_compilation")
            .header(rocket::http::ContentType::Form)
            .body(format!(
                "demo_id={}&ddl_build={}",
                "t001",
                serde_json::to_string(&ddl_build).unwrap()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(EnsureCompilationResponse {
                status: "OK".into(),
                message: "".into(),
            })
        );
    }

    #[test]
    fn test_ensure_compilation_missing_dockerfile() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: "https://github.com/kidanger/ipol-demo-zero".into(),
            rev: "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79".into(),
            dockerfile: "missing".into(),
        };
        let response = client
            .post("/api/demorunner/ensure_compilation")
            .header(rocket::http::ContentType::Form)
            .body(format!(
                "demo_id={}&ddl_build={}",
                "t002",
                serde_json::to_string(&ddl_build).unwrap()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(EnsureCompilationResponse {
                status: "KO".into(),
                message: "Couldn't find dockerfile: missing".into(),
            })
        );
    }

    #[test]
    fn test_ensure_compilation_invalid_git_commit() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: "https://github.com/kidanger/ipol-demo-zero".into(),
            rev: "invalid".into(),
            dockerfile: ".ipol/Dockerfile".into(),
        };
        let response = client
            .post("/api/demorunner/ensure_compilation")
            .header(rocket::http::ContentType::Form)
            .body(format!(
                "demo_id={}&ddl_build={}",
                "t003",
                serde_json::to_string(&ddl_build).unwrap()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(EnsureCompilationResponse {
                status: "KO".into(),
                message: "revspec 'invalid' not found; class=Reference (4); code=NotFound (-3)"
                    .into(),
            })
        );
    }

    #[test]
    fn test_exec_and_wait() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let params = RunParams::from([
            ("x".into(), ParamValue::PosInt(1)),
            ("y".into(), ParamValue::Float(2.5)),
            ("z".into(), ParamValue::String("t001".into())),
            ("a".into(), ParamValue::Bool(true)),
            ("b".into(), ParamValue::NegInt(-2)),
            ("param space".into(), ParamValue::String("hi world".into())),
        ]);
        let ddl_run = "test $z = $IPOL_DEMOID";
        let response = client
            .post("/api/demorunner/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                "test_exec_and_wait",
                serde_json::to_string(&params).unwrap(),
                serde_json::to_string(&ddl_run).unwrap(),
                10,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(ExecAndWaitResponse {
                status: "OK".into(),
                message: "".into(),
            })
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_exec_and_wait_non_zero_exit_code() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let params = RunParams::new();
        let ddl_run = "exit 5";
        let response = client
            .post("/api/demorunner/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                "test_exec_and_wait_non_zero_exit_code",
                serde_json::to_string(&params).unwrap(),
                serde_json::to_string(&ddl_run).unwrap(),
                10,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(ExecAndWaitResponse {
                status: "KO".into(),
                message: "Non-zero exit code (5)".into(),
            })
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_exec_and_wait_timeout() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");

        let params = RunParams::new();
        let ddl_run = "echo bla; sleep 2; echo blo";
        let response = client
            .post("/api/demorunner/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                "test_exec_and_wait_timeout",
                serde_json::to_string(&params).unwrap(),
                serde_json::to_string(&ddl_run).unwrap(),
                1,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(ExecAndWaitResponse {
                status: "KO".into(),
                message: "Execution timeout".into(),
            })
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_url_of_git_repository() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path();
        let url = url_of_git_repository(path);
        assert_eq!(url, None);

        let url1 = String::from("https://github.com/kidanger/ipol-demo-zero");
        let r = prepare_git(path, &url1, "master");
        dbg!(&r);
        assert!(r.is_ok());

        let url = url_of_git_repository(path);
        assert_eq!(url, Some(url1));

        let url2 = String::from("https://github.com/kidanger/ipol-demo-zero.git");
        let r = prepare_git(path, &url2, "master");
        dbg!(&r);
        assert!(r.is_ok());

        let url = url_of_git_repository(path);
        assert_eq!(url, Some(url2));
    }
}
