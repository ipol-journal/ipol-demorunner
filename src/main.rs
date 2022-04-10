use std::time::Duration;

#[macro_use]
extern crate rocket;
use rocket::http::hyper::Body;
use rocket::serde::json::{Json, Value};
use rocket::serde::{Deserialize, Serialize};

use bollard::container::{Config, CreateContainerOptions, LogOutput, LogsOptions};
use bollard::{image::BuildImageOptions, Docker};

use futures_util::stream::StreamExt;
use git2::Repository;
use tar::Builder;

//#[derive(Debug, Serialize, Deserialize, Display)]
type DemoID = String;

//#[derive(Debug, Serialize, Deserialize, Display)]
type RunKey = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RunParams {}

type DDLRun = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DDLBuild {
    url: String,
    rev: String,
    dockerfile: String,
}

#[derive(Debug, Serialize)]
struct PingResponse {
    message: String,
    ping: String,
}

#[post("/")]
fn ping() -> Json<PingResponse> {
    Json(PingResponse {
        message: "OK".into(),
        ping: "pong".into(),
    })
}

#[derive(Debug, Serialize)]
struct ShutdownResponse {
    status: String,
}

#[get("/")]
fn shutdown() -> Json<ShutdownResponse> {
    todo!();
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct Workload {
    status: String,
    workload: f32,
}

#[get("/")]
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

#[get("/")]
fn get_stats() -> Json<Stats> {
    todo!();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnsureCompilationRequest {
    demo_id: DemoID,
    ddl_build: DDLBuild,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct EnsureCompilationResponse {
    status: String,
    message: String,
}

#[post("/", data = "<req>")]
async fn ensure_compilation(
    req: Json<EnsureCompilationRequest>,
) -> Json<EnsureCompilationResponse> {
    dbg!(req.clone());

    // TODO: keep a cache somewhere else
    let dst_path = format!("/tmp/t/{}", req.demo_id);

    // TODO: detect if we actually need to recompile

    let repo = if !std::path::Path::new(&dst_path).exists() {
        let url = req.ddl_build.url.clone();
        // TODO: credentials
        // TODO: shallow clone
        match Repository::clone_recurse(&url, &dst_path) {
            Ok(repo) => repo,
            Err(e) => panic!("failed to clone: {}", e),
        }
    } else {
        match Repository::open(&dst_path) {
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

    let vec = {
        let mut ar = Builder::new(Vec::new());
        // TODO: exclude .git
        ar.append_dir_all(".", dst_path).unwrap();
        let vec = ar.into_inner();
        vec.unwrap()
    };
    let tar = Body::from(vec);
    //std::fs::write("/tmp/code.tar", &vec.clone()).unwrap();

    let docker = Docker::connect_with_socket_defaults().unwrap();
    let image_name = format!("ipol-demo-{}", req.demo_id);
    let build_image_options = BuildImageOptions {
        dockerfile: req.ddl_build.dockerfile.as_str(),
        t: &image_name,
        q: false,
        ..Default::default()
    };
    let mut image_build_stream = docker.build_image(build_image_options, None, Some(tar));

    while let Some(msg) = image_build_stream.next().await {
        // TODO: write to build.log
        dbg!(&msg);
        if let Ok(info) = msg {
            if let Some(err) = info.error {
                return Json(EnsureCompilationResponse {
                    status: "KO".to_string(),
                    message: err,
                });
            }
        }
    }

    Json(EnsureCompilationResponse {
        status: "OK".to_string(),
        message: "".to_string(),
    })
}

#[derive(Debug, Deserialize)]
struct TestCompilationRequest {
    ddl_build: DDLBuild,
    compilation_path: String,
}

#[post("/", data = "<req>")]
fn test_compilation(req: Json<TestCompilationRequest>) -> Value {
    todo!();
}

#[derive(Debug, Deserialize)]
struct DeleteCompilationRequest {
    demo_id: DemoID,
}

#[post("/", data = "<req>")]
fn delete_compilation(req: Json<DeleteCompilationRequest>) {
    todo!();
}

#[serde_with::serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExecAndWaitRequest {
    demo_id: DemoID,
    key: RunKey,
    params: RunParams,
    ddl_run: DDLRun,
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ExecAndWaitResponse {
    status: String,
    message: String,
}

#[post("/", data = "<req>")]
async fn exec_and_wait(req: Json<ExecAndWaitRequest>) -> Json<ExecAndWaitResponse> {
    dbg!(req.clone());

    let image_name = format!("ipol-demo-{}", req.demo_id);

    let docker = Docker::connect_with_socket_defaults().unwrap();

    let host_config = bollard::service::HostConfig {
        auto_remove: Some(true),
        // TODO: use the usual exec folder and check that that the current run exists
        binds: Some(vec!["/tmp/t/exec/:/workdir".to_string()]),
        ..Default::default()
    };

    let name = format!("ipol-exec-{}-{}", req.demo_id, req.key);
    let options = Some(CreateContainerOptions {
        name: name.as_str(),
    });
    let env_demoid = format!("IPOL_DEMOID={}", req.demo_id);
    let env_key = format!("IPOL_KEY={}", req.key);
    let env = vec![env_demoid.as_str(), env_key.as_str()];
    let config = Config {
        image: Some(image_name.as_str()),
        // TODO: uid:gid from a config file
        user: Some("1000:1000"),
        cmd: Some(vec!["/bin/bash", "-c", req.ddl_run.as_str()]),
        env: Some(env),
        working_dir: Some("/workdir"),
        host_config: Some(host_config),
        ..Default::default()
    };
    let id = docker.create_container(options, config).await.unwrap().id;
    docker.start_container::<String>(&id, None).await.unwrap();

    dbg!(&id);

    {
        // TODO: handle timeout
        let options = Some(LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            timestamps: true,
            ..Default::default()
        });
        let mut logs = docker.logs(&id, options);
        while let Some(msg) = logs.next().await {
            // TODO: write to stdout.txt and stderr.txt
            match msg {
                Ok(LogOutput::StdOut { message }) => {
                    println!("stdout: {message:#?}");
                }
                Ok(LogOutput::StdErr { message }) => {
                    println!("stderr: {message:#?}");
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
        .mount("/", routes![index])
        .mount("/ping", routes![ping])
        .mount("/shutdown", routes![shutdown])
        .mount("/get_workload", routes![get_workload])
        .mount("/get_stats", routes![get_stats])
        .mount("/ensure_compilation", routes![ensure_compilation])
        .mount("/test_compilation", routes![test_compilation])
        .mount("/delete_compilation", routes![delete_compilation])
        .mount("/exec_and_wait", routes![exec_and_wait])
}

#[cfg(test)]
mod test {
    use super::rocket;
    use super::*;
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    // TODO: remove git repositories and docker images

    #[test]
    fn test_get_workfload() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get("/get_workload").dispatch();
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
        let response = client
            .post("/ensure_compilation")
            .json(&EnsureCompilationRequest {
                demo_id: "t001".into(),
                ddl_build: DDLBuild {
                    url: "./ZERO".into(),
                    rev: "origin/master".into(),
                    dockerfile: "Dockerfile".into(),
                },
            })
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
        let response = client
            .post("/exec_and_wait")
            .json(&ExecAndWaitRequest {
                demo_id: "t001".into(),
                key: "test_exec_and_wait".into(),
                params: RunParams {},
                ddl_run: "echo foo; sleep 2; echo bar".into(),
                timeout: Duration::from_secs(10),
            })
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
