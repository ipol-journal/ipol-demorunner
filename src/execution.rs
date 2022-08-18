use std::time::Duration;

use bollard::models::DeviceRequest;
use rocket::form::Form;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::fs;
use rocket::tokio::io::AsyncWriteExt;
use rocket::tokio::time::error::Elapsed;
use rocket::tokio::time::{timeout_at, Instant};
use rocket::State;

use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, LogOutput, LogsOptions,
    RemoveContainerOptions,
};
use bollard::Docker;

use futures_util::stream::StreamExt;

use crate::config;
use crate::model::*;

#[derive(Debug, FromForm)]
pub struct ExecAndWaitRequest<'a> {
    #[field(validate=validate_demoid())]
    demo_id: DemoID,
    #[field(validate=validate_runkey())]
    key: RunKey,
    params: Json<RunParams>,
    ddl_run: DDLRun,
    timeout: Option<u64>,
    inputs: Vec<rocket::fs::TempFile<'a>>,
}

#[derive(Responder)]
#[response(status = 200, content_type = "application/zip")]
pub struct ExecAndWaitResponse {
    zip: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct AlgoInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_time: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecInfo {
    key: RunKey,
    params: RunParams,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    algo_info: AlgoInfo,
}

#[derive(Debug, thiserror::Error)]
enum ExecError {
    #[error("Non-zero exit code ({0}): {1}")]
    NonZeroExitCode(i64, String),
    #[error("{0}")]
    IO(#[from] std::io::Error),
    #[error("{0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("IPOLTimeoutError: Execution timeout")]
    Timeout(#[from] Elapsed),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
}

#[derive(Debug, thiserror::Error)]
pub enum ExecAndWaitInternalError {
    #[error("io: {0}")]
    IO(#[from] std::io::Error),
    #[error("io path: {0}")]
    IOPath(#[from] std::path::StripPrefixError),
    #[error("zip: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("json: {0}")]
    Json(#[from] serde_json::error::Error),
}

impl<'r> Responder<'r, 'static> for ExecAndWaitInternalError {
    fn respond_to(self, req: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        let string = self.to_string();
        rocket::Response::build_from(string.respond_to(req)?)
            .status(rocket::http::Status::InternalServerError)
            .ok()
    }
}

fn zip_dir_into_bytes(dir: &std::path::Path) -> Result<Vec<u8>, ExecAndWaitInternalError> {
    let writer = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(writer);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);

    for file in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        let filename = file.path();

        let name_in_zip = filename.strip_prefix(dir)?;
        let name_in_zip = name_in_zip.to_str().unwrap_or_default();
        if name_in_zip.is_empty() {
            continue;
        }

        if file.file_type().is_file() {
            if let Ok(mut file) = std::fs::File::open(filename) {
                zip.start_file(name_in_zip.to_string(), options)?;
                std::io::copy(&mut file, &mut zip)?;
            }
        } else if file.file_type().is_dir() {
            zip.add_directory(name_in_zip.to_string(), options).ok();
        }
    }

    Ok(zip.finish()?.into_inner())
}

async fn exec_and_wait_inner(
    req: &mut ExecAndWaitRequest<'_>,
    config: &config::Config,
    outdir: &std::path::Path,
) -> Result<Duration, ExecError> {
    dbg!(&req);
    // canonicalize for docker volumes
    let outdir = fs::canonicalize(outdir).await?;

    for input in &mut req.inputs {
        if let Some(filename) = input.raw_name() {
            let filename = filename.dangerous_unsafe_unsanitized_raw().as_str();
            let filename = std::path::Path::new(filename);

            let dst = safe_path::scoped_join(&outdir, filename)?;
            input.persist_to(dst).await?;
        }
    }

    let image_name = format!("{}{}:latest", config.docker_image_prefix, req.demo_id);
    let exec_mountpoint = &config.exec_workdir_in_docker;

    let mut stderr = fs::File::create(outdir.join("stderr.txt")).await?;
    let mut stdout = fs::File::create(outdir.join("stdout.txt")).await?;

    let device_requests = if config.gpus.is_empty() {
        None
    } else {
        Some(vec![DeviceRequest {
            driver: None,
            count: None,
            device_ids: Some(config.gpus.clone()),
            capabilities: Some(vec![vec!["gpu".into()]]),
            options: None,
        }])
    };

    let host_config = bollard::models::HostConfig {
        binds: Some(vec![format!(
            "{}:{}",
            outdir.clone().to_str().unwrap(),
            exec_mountpoint,
        )]),
        device_requests,
        ..Default::default()
    };

    let name = format!("{}{}-{}", config.docker_exec_prefix, req.demo_id, req.key);
    let options = Some(CreateContainerOptions {
        name: name.as_str(),
    });

    let env = req
        .params
        .0
        .clone()
        .into_iter()
        .chain(config.env_vars.clone().into_iter())
        .collect::<RunParams>()
        .to_env_vec(&req.demo_id, &req.key);
    let env = env.iter().map(|s| s as &str).collect();
    let container_config = Config {
        image: Some(image_name.as_str()),
        user: Some(&config.user_uid_gid),
        cmd: Some(vec!["/bin/bash", "-c", req.ddl_run.as_str()]),
        env: Some(env),
        working_dir: Some(exec_mountpoint),
        host_config: Some(host_config),
        ..Default::default()
    };

    let docker = Docker::connect_with_socket_defaults()?;
    let id = docker.create_container(options, container_config).await?.id;
    dbg!(&id);

    scopeguard::defer! {
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

    let mut output = String::new();
    let max_timeout = config.max_timeout;
    let timeout = req.timeout.map_or(max_timeout, |v| max_timeout.min(v));
    let deadline = Instant::now() + Duration::from_secs(timeout);
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
                    output.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(LogOutput::StdErr { message }) => {
                    println!("stderr: {message:#?}");
                    stderr.write_all(&message).await?;
                    output.push_str(&String::from_utf8_lossy(&message));
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

    let mut duration = None;
    if let Some(state) = inspect_response.state {
        if let Some(exit_code) = state.exit_code {
            if exit_code != 0 {
                return Err(ExecError::NonZeroExitCode(exit_code, output));
            }
        }

        if let (Some(start), Some(end)) = (state.started_at, state.finished_at) {
            let now = chrono::Utc::now().with_timezone(&chrono::FixedOffset::east(0));
            let start = chrono::DateTime::parse_from_rfc3339(&start).unwrap_or(now);
            let end = chrono::DateTime::parse_from_rfc3339(&end).unwrap_or(now);
            duration = (end - start).to_std().ok();
        }
    }

    let duration = duration.unwrap_or_default();
    Ok(duration)
}

#[post("/exec_and_wait", data = "<req>")]
pub async fn exec_and_wait(
    mut req: Form<ExecAndWaitRequest<'_>>,
    config: &State<config::Config>,
) -> Result<ExecAndWaitResponse, ExecAndWaitInternalError> {
    let tmpdir = tempfile::TempDir::new()?;
    let outdir = tmpdir.path();

    let state = exec_and_wait_inner(&mut req, config, outdir).await;

    let key = req.key.clone();
    let params = req.params.0.clone();
    let exec_info = match state {
        Ok(duration) => ExecInfo {
            key,
            params,
            status: "OK".into(),
            error: None,
            algo_info: AlgoInfo {
                error_message: None,
                run_time: Some(duration.as_secs_f64()),
            },
        },
        Err(err) => match err {
            ExecError::Timeout(_) => ExecInfo {
                key,
                params,
                status: "KO".into(),
                error: Some("IPOLTimeoutError".into()),
                algo_info: AlgoInfo {
                    error_message: Some(err.to_string()),
                    run_time: None,
                },
            },
            _ => ExecInfo {
                key,
                params,
                status: "KO".into(),
                error: Some(err.to_string()),
                algo_info: AlgoInfo {
                    error_message: Some(err.to_string()),
                    run_time: None,
                },
            },
        },
    };

    let mut exec_info_file = fs::File::create(outdir.join("exec_info.json")).await?;
    let exec_info = serde_json::to_string_pretty(&exec_info)?;
    exec_info_file.write_all(exec_info.as_bytes()).await?;

    let zip = zip_dir_into_bytes(outdir)?;
    Ok(ExecAndWaitResponse { zip })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::main_rocket;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;

    fn extract_exec_info(resp: &[u8]) -> ExecInfo {
        let reader = std::io::Cursor::new(resp);
        let mut zip = zip::ZipArchive::new(reader).unwrap();
        let file = zip.by_name("exec_info.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    #[test]
    fn test_exec_and_wait() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");

        let key = "test_exec_and_wait".to_string();
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
            .post("/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                key,
                serde_json::to_string(&params).unwrap(),
                ddl_run,
                10,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_bytes().unwrap();
        let exec_info = extract_exec_info(&response);
        dbg!(&exec_info);
        assert_eq!(exec_info.status, "OK");
        assert_eq!(exec_info.key, key);
        assert_eq!(exec_info.params, params);
        assert_eq!(exec_info.error, None);
        assert_eq!(exec_info.algo_info.error_message, None);
        assert!(exec_info.algo_info.run_time.is_some());
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_exec_and_wait_non_zero_exit_code() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");

        let key = "test_exec_and_wait_non_zero_exit_code".to_string();
        let params = RunParams::new();
        let ddl_run = "echo a; exit 5; echo b;";
        let response = client
            .post("/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                key,
                serde_json::to_string(&params).unwrap(),
                &ddl_run,
                10,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_bytes().unwrap();
        let exec_info = extract_exec_info(&response);
        dbg!(&exec_info);
        assert_eq!(exec_info.status, "KO");
        assert_eq!(exec_info.key, key);
        assert_eq!(exec_info.params, params);
        assert_eq!(exec_info.error, Some("Non-zero exit code (5): a\n".into()));
        assert_eq!(
            exec_info.algo_info.error_message,
            Some("Non-zero exit code (5): a\n".into())
        );
        assert!(exec_info.algo_info.run_time.is_none());
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_exec_and_wait_timeout() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");

        let key = "test_exec_and_wait_timeout".to_string();
        let params = RunParams::new();
        let ddl_run = "sleep 2";
        let response = client
            .post("/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                key,
                serde_json::to_string(&params).unwrap(),
                &ddl_run,
                1,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_bytes().unwrap();
        let exec_info = extract_exec_info(&response);
        dbg!(&exec_info);
        assert_eq!(exec_info.status, "KO");
        assert_eq!(exec_info.key, key);
        assert_eq!(exec_info.params, params);
        assert_eq!(exec_info.error, Some("IPOLTimeoutError".into()));
        assert_eq!(
            exec_info.algo_info.error_message,
            Some("IPOLTimeoutError: Execution timeout".into())
        );
        assert!(exec_info.algo_info.run_time.is_none());
        std::thread::sleep(Duration::from_secs(1));
    }

    #[test]
    fn test_exec_and_wait_run_time() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");

        let key = "test_exec_and_wait_run_time".to_string();
        let params = RunParams::new();
        let ddl_run = "sleep 2";
        let response = client
            .post("/exec_and_wait")
            .header(ContentType::Form)
            .body(format!(
                "demo_id={}&key={}&params={}&ddl_run={}&timeout={}",
                "t001",
                key,
                serde_json::to_string(&params).unwrap(),
                &ddl_run,
                10,
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        let response = response.into_bytes().unwrap();
        let exec_info = extract_exec_info(&response);
        dbg!(&exec_info);
        assert_eq!(exec_info.status, "OK");
        assert_eq!(exec_info.key, key);
        assert_eq!(exec_info.params, params);
        assert_eq!(exec_info.error, None);
        assert_eq!(exec_info.algo_info.error_message, None);
        assert!(exec_info.algo_info.run_time > Some(1.5));
        std::thread::sleep(Duration::from_secs(1));
    }
}
