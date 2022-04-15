use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

#[macro_use]
extern crate rocket;
use rocket::fairing::AdHoc;
use rocket::form::Form;
use rocket::http::hyper::Body;
use rocket::serde::json::{Json, Value};
use rocket::serde::{Deserialize, Serialize};
use rocket::State;

#[macro_use(defer)]
extern crate scopeguard;

use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, LogOutput, LogsOptions,
    RemoveContainerOptions,
};
use bollard::{image::BuildImageOptions, Docker};

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
}

//#[derive(Debug, Serialize, Deserialize, Display)]
type DemoID = String;

//#[derive(Debug, Serialize, Deserialize, Display)]
type RunKey = String;

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
fn shutdown() -> Json<ShutdownResponse> {
    todo!();
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
    demo_id: DemoID,
    ddl_build: Json<DDLBuild>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnsureCompilationResponse {
    status: String,
    message: String,
}

#[post("/ensure_compilation", data = "<req>")]
async fn ensure_compilation(
    req: Form<EnsureCompilationRequest>,
    config: &State<RunnerConfig>,
) -> Json<EnsureCompilationResponse> {
    dbg!(&req);

    // TODO: validate demo_id

    let compilation_path = PathBuf::from(&config.compilation_root).join(&req.demo_id);
    let srcdir = PathBuf::from(&compilation_path).join("src");
    let logfile = PathBuf::from(&compilation_path).join("build.log");
    std::fs::create_dir_all(&compilation_path).unwrap();
    let mut buildlog = std::fs::File::create(logfile).unwrap();

    // TODO: detect if we actually need to recompile
    // TODO: if the url changes, reclone

    let repo = if !std::path::Path::new(&srcdir).exists() {
        let url = req.ddl_build.url.clone();
        // TODO: credentials
        // TODO: shallow clone
        match Repository::clone_recurse(&url, &srcdir) {
            Ok(repo) => repo,
            Err(e) => panic!("failed to clone: {}", e),
        }
    } else {
        match Repository::open(&srcdir) {
            Ok(repo) => repo,
            Err(e) => panic!("failed to clone: {}", e),
        }
    };

    {
        let mut remote = repo
            .find_remote("origin")
            .expect("Failed to find remote 'origin'");
        // TODO: shallow fetch the rev
        remote
            .fetch(&["master"], None, None)
            .expect("Failed to fetch 'origin'");
    }

    {
        // TODO: support "master" as rev instead of "origin/master"
        let rev = req.ddl_build.rev.clone();
        let object = repo.revparse_single(&rev).expect("Object not found");
        dbg!(object.clone());
        repo.checkout_tree(&object, None)
            .expect("Failed to checkout");
        repo.set_head_detached(object.id())
            .expect("Failed to set HEAD");
    }

    // TODO: check that the dockerfile exists

    let vec = {
        let mut ar = Builder::new(Vec::new());
        // TODO: exclude .git
        ar.append_dir_all(".", srcdir).unwrap();
        let vec = ar.into_inner();
        vec.unwrap()
    };
    let tar = Body::from(vec);
    //std::fs::write("/tmp/code.tar", &vec.clone()).unwrap();

    let docker = Docker::connect_with_socket_defaults().unwrap();
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
                buildlog.write_all(stream.as_bytes()).unwrap();
            }
            if let Some(err) = info.error {
                buildlog.write_all(err.as_bytes()).unwrap();
                compilation_error = Some(err);
            }
        }
    }

    Json(if let Some(err) = compilation_error {
        EnsureCompilationResponse {
            status: "KO".to_string(),
            message: err,
        }
    } else {
        EnsureCompilationResponse {
            status: "OK".to_string(),
            message: "".to_string(),
        }
    })
}

#[derive(Debug, Deserialize)]
struct TestCompilationRequest {
    ddl_build: DDLBuild,
    compilation_path: String,
}

#[post("/test_compilation", data = "<req>")]
fn test_compilation(req: Json<TestCompilationRequest>) -> Value {
    todo!();
}

#[derive(Debug, Deserialize)]
struct DeleteCompilationRequest {
    demo_id: DemoID,
}

#[post("/delete_compilation", data = "<req>")]
fn delete_compilation(req: Json<DeleteCompilationRequest>) {
    todo!();
}

#[derive(Debug, FromForm)]
struct ExecAndWaitRequest {
    demo_id: DemoID,
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

#[post("/exec_and_wait", data = "<req>")]
async fn exec_and_wait(
    req: Form<ExecAndWaitRequest>,
    config: &State<RunnerConfig>,
) -> Json<ExecAndWaitResponse> {
    dbg!(&req);

    // TODO: validate demo_id and key

    let outdir = PathBuf::from(&config.execution_root)
        .join(&req.demo_id)
        .join(&req.key);
    std::fs::create_dir_all(&outdir).unwrap();
    let outdir = std::fs::canonicalize(outdir).unwrap();

    let image_name = format!("{}{}:latest", config.docker_image_prefix, req.demo_id);
    let exec_mountpoint = &config.exec_workdir_in_docker;

    let mut stderr = std::fs::File::create(outdir.join("stderr.txt")).unwrap();
    let mut stdout = std::fs::File::create(outdir.join("stdout.txt")).unwrap();

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
        // TODO: uid:gid from a config file
        user: Some("1000:1000"),
        cmd: Some(vec!["/bin/bash", "-c", req.ddl_run.as_str()]),
        env: Some(env),
        working_dir: Some(exec_mountpoint),
        host_config: Some(host_config),
        ..Default::default()
    };

    let docker = Docker::connect_with_socket_defaults().unwrap();
    let id = docker.create_container(options, config).await.unwrap().id;

    defer! {
        let docker = docker.clone();
        let name = name.clone();
        rocket::tokio::spawn(async move {
            let options = Some(RemoveContainerOptions {
                force: true,
                ..Default::default()
            });
            docker.remove_container(&name, options).await.unwrap();
        });
    }

    docker.start_container::<String>(&id, None).await.unwrap();

    dbg!(&id);

    {
        // TODO: handle timeout
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
                    stdout.write_all(&message).unwrap();
                }
                Ok(LogOutput::StdErr { message }) => {
                    println!("stderr: {message:#?}");
                    stderr.write_all(&message).unwrap();
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
    }

    let options = Some(InspectContainerOptions { size: false });
    let inspect_response = docker.inspect_container(&name, options).await.unwrap();
    let state = inspect_response.state.unwrap();
    dbg!(&state);

    if state.exit_code != Some(0) {
        return Json(ExecAndWaitResponse {
            status: "KO".into(),
            message: "".into(),
        });
    }

    Json(ExecAndWaitResponse {
        status: "OK".into(),
        message: "".into(),
    })
}

#[get("/")]
fn index() -> &'static str {
    "This is the IPOL DemoRunner module (docker)"
}

#[launch]
fn rocket() -> _ {
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
    }
}
