use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use bollard::models::DeviceRequest;
use bollard::service::HostConfig;
use rocket::response::Responder;

use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::fs;
use rocket::tokio::io::AsyncWriteExt;
use rocket::tokio::time::error::Elapsed;
use rocket::tokio::time::{timeout_at, Instant};

use bollard::container::{
    Config, CreateContainerOptions, InspectContainerOptions, LogOutput, LogsOptions,
    RemoveContainerOptions,
};
use bollard::Docker;

use futures_util::stream::StreamExt;

use crate::compilation::get_git_revision;
use crate::config;
use crate::model::*;

#[derive(Debug)]
pub struct ExecAndWaitRequest<'a, 'b> {
    demo_id: DemoID,
    key: RunKey,
    params: RunParams,
    ddl_run: DDLRun,
    timeout: Option<u64>,
    inputs: &'b mut [rocket::fs::TempFile<'a>],
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
    #[error("ipol-demorunner/exec/git: {0}")]
    Git(#[from] git2::Error),
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

#[tracing::instrument(skip(dir))]
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
                tracing::debug!("copy {filename:?} -> {name_in_zip:?}");
            }
        } else if file.file_type().is_dir() {
            zip.add_directory(name_in_zip.to_string(), options).ok();
            tracing::debug!("add directory {name_in_zip:?}");
        }
    }

    Ok(zip.finish()?.into_inner())
}

#[tracing::instrument(skip(input, outdir))]
async fn save_input<'a>(
    input: &mut rocket::fs::TempFile<'a>,
    outdir: &Path,
) -> Result<(), ExecError> {
    if let Some(filename) = input.raw_name() {
        let filename = filename.dangerous_unsafe_unsanitized_raw().as_str();
        let filename = std::path::Path::new(filename);

        let dst = safe_path::scoped_join(outdir, filename)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent).await?;
        }
        let size = input.len();
        tracing::debug!("saving input {filename:?} ({size} bytes) to {dst:?}");
        input.persist_to(dst).await?;
    }
    Ok(())
}

fn get_device_requests(config: &config::Config) -> Option<Vec<DeviceRequest>> {
    if config.gpus.is_empty() {
        None
    } else {
        Some(vec![DeviceRequest {
            driver: None,
            count: None,
            device_ids: Some(config.gpus.clone()),
            capabilities: Some(vec![vec!["gpu".into()]]),
            options: None,
        }])
    }
}

fn get_docker_binds(config: &config::Config, outdir: &Path) -> Option<Vec<String>> {
    let exec_mountpoint = &config.exec_workdir_in_docker;
    Some(vec![format!(
        "{}:{}",
        outdir.to_str().unwrap(),
        exec_mountpoint,
    )])
}

fn get_docker_host_config(config: &config::Config, outdir: &Path) -> HostConfig {
    let device_requests = get_device_requests(config);
    let binds = get_docker_binds(config, outdir);
    HostConfig {
        binds,
        device_requests,
        ..Default::default()
    }
}

#[tracing::instrument(skip(docker))]
async fn remove_container(docker: Docker, name: &str) -> Result<(), bollard::errors::Error> {
    let options = Some(RemoveContainerOptions {
        force: true,
        ..Default::default()
    });
    tracing::debug!("removing container {name:?}");
    docker.remove_container(name, options).await
}

fn compute_timeout_deadline(config: &config::Config, req_timeout: Option<u64>) -> Instant {
    let max_timeout = config.max_timeout;
    let timeout = req_timeout.map_or(max_timeout, |v| max_timeout.min(v));
    Instant::now() + Duration::from_secs(timeout)
}

#[tracing::instrument(skip(docker, deadline, outdir))]
async fn read_logs_with_timeout(
    docker: &Docker,
    deadline: Instant,
    id: &str,
    outdir: &Path,
) -> Result<String, ExecError> {
    let mut output = String::new();

    let mut stderr = fs::File::create(outdir.join("stderr.txt")).await?;
    let mut stdout = fs::File::create(outdir.join("stdout.txt")).await?;
    timeout_at(deadline, async {
        let options = Some(LogsOptions::<String> {
            follow: true,
            stdout: true,
            stderr: true,
            ..Default::default()
        });
        let mut logs = docker.logs(id, options);
        while let Some(msg) = logs.next().await {
            match msg {
                Ok(LogOutput::StdOut { message }) => {
                    tracing::info!("stdout: {message:#?}");
                    stdout.write_all(&message).await?;
                    output.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(LogOutput::StdErr { message }) => {
                    tracing::info!("stderr: {message:#?}");
                    stderr.write_all(&message).await?;
                    output.push_str(&String::from_utf8_lossy(&message));
                }
                Ok(LogOutput::StdIn { message }) => {
                    tracing::info!("stdin: {message:#?}");
                }
                Ok(LogOutput::Console { message }) => {
                    tracing::info!("console: {message:#?}");
                }
                Err(e) => {
                    tracing::error!("{:?}", e);
                }
            };
        }
        Ok::<(), ExecError>(())
    })
    .await??;

    stdout.flush().await?;
    stderr.flush().await?;
    Ok(output)
}

#[tracing::instrument(skip(req, config, outdir))]
async fn exec_and_wait_inner<'a, 'b>(
    req: &mut ExecAndWaitRequest<'a, 'b>,
    config: &config::Config,
    outdir: &std::path::Path,
) -> Result<Duration, ExecError> {
    tracing::debug!("{req:?}");

    let docker = Docker::connect_with_socket_defaults()?;

    // canonicalize for docker volumes
    let outdir = fs::canonicalize(outdir).await?;

    for input in &mut *req.inputs {
        save_input(input, &outdir).await?;
    }

    // TODO/IPOL: it would be better if the git_rev were provided in the payload
    let src_path = PathBuf::from(&config.compilation_root)
        .join(req.demo_id.as_ref())
        .join("src");
    let git_rev = get_git_revision(&src_path)?;

    let registry = config
        .registry_url
        .as_ref()
        .map_or(String::new(), |url| (url.clone() + "/"));
    let image_name = format!(
        "{}{}{}:{}",
        registry, config.docker_image_prefix, &req.demo_id, git_rev
    );

    if config.registry_url.is_some() {
        let mut stream = docker.create_image(
            Some(bollard::image::CreateImageOptions {
                from_image: image_name.clone(),
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(msg) = stream.next().await {
            if let Err(err) = msg {
                warn!("exec/pull: {}", err);
            }
        }
    }

    let name = format!("{}{}-{}", config.docker_exec_prefix, &req.demo_id, req.key);
    let options = Some(CreateContainerOptions {
        name: name.as_str(),
        platform: None,
    });

    let env = req
        .params
        .clone()
        .into_iter()
        .chain(config.env_vars.clone().into_iter())
        .collect::<RunParams>()
        .to_env_vec(&req.demo_id, &req.key);
    let env = env.iter().map(|s| s as &str).collect();
    let exec_mountpoint = &config.exec_workdir_in_docker;
    let host_config = get_docker_host_config(config, &outdir);
    let container_config = Config {
        image: Some(image_name.as_str()),
        user: Some(&config.user_uid_gid),
        cmd: Some(vec!["/bin/bash", "-c", req.ddl_run.as_str()]),
        env: Some(env),
        working_dir: Some(exec_mountpoint),
        host_config: Some(host_config),
        ..Default::default()
    };

    tracing::debug!(name = name, image_name = image_name);
    let id = docker.create_container(options, container_config).await?.id;
    tracing::debug!(id = id);

    scopeguard::defer! {
        let docker = docker.clone();
        let name = name.clone();
        rocket::tokio::spawn(async move {
            if let Err(e) = remove_container(docker, &name).await {
                tracing::error!("{:?}", e);
            }
        });
    }

    tracing::debug!("starting container {id:?}");
    docker.start_container::<String>(&id, None).await?;

    let deadline = compute_timeout_deadline(config, req.timeout);
    let output = read_logs_with_timeout(&docker, deadline, &id, &outdir).await?;

    let options = Some(InspectContainerOptions::default());
    let inspect_response = docker.inspect_container(&name, options).await?;

    let mut duration = None;
    if let Some(state) = inspect_response.state {
        if let Some(exit_code) = state.exit_code {
            if exit_code != 0 {
                tracing::debug!("container exited with code {exit_code}");
                return Err(ExecError::NonZeroExitCode(exit_code, output));
            }
        }

        if let (Some(start), Some(end)) = (state.started_at, state.finished_at) {
            let timezone = chrono::FixedOffset::east_opt(0).unwrap();
            let now = chrono::Utc::now().with_timezone(&timezone);
            let start = chrono::DateTime::parse_from_rfc3339(&start).unwrap_or(now);
            let end = chrono::DateTime::parse_from_rfc3339(&end).unwrap_or(now);
            duration = (end - start).to_std().ok();
        }
    }

    let duration = duration.unwrap_or_default();
    Ok(duration)
}

async fn save_exec_info(
    exec_info: &ExecInfo,
    outdir: &Path,
) -> Result<(), ExecAndWaitInternalError> {
    let mut exec_info_file = fs::File::create(outdir.join("exec_info.json")).await?;
    let exec_info = serde_json::to_string_pretty(exec_info)?;
    exec_info_file.write_all(exec_info.as_bytes()).await?;
    exec_info_file.flush().await?;
    Ok(())
}

pub mod http {
    use rocket::form::Form;
    use rocket::serde::json::Json;
    use rocket::State;

    use super::{
        exec_and_wait_inner, save_exec_info, zip_dir_into_bytes, AlgoInfo,
        ExecAndWaitInternalError, ExecAndWaitRequest, ExecError, ExecInfo,
    };
    use crate::config;
    use crate::model::{DDLRun, DemoID, RunKey, RunParams};

    #[derive(Responder)]
    #[response(status = 200, content_type = "application/zip")]
    pub struct ExecAndWaitResponse {
        zip: Vec<u8>,
    }

    #[tracing::instrument(skip(config, inputs))]
    #[post(
        "/exec_and_wait/<demo_id>?<key>&<ddl_run>&<timeout>&<parameters>",
        data = "<inputs>"
    )]
    pub async fn exec_and_wait<'a>(
        demo_id: DemoID,
        key: RunKey,
        ddl_run: DDLRun,
        timeout: Option<u64>,
        parameters: Json<RunParams>,
        mut inputs: Form<Vec<rocket::fs::TempFile<'a>>>,
        config: &State<config::Config>,
    ) -> Result<ExecAndWaitResponse, ExecAndWaitInternalError> {
        let tmpdir = tempfile::TempDir::new()?;
        let outdir = tmpdir.path();

        let mut req = ExecAndWaitRequest {
            demo_id,
            key,
            ddl_run,
            timeout,
            params: parameters.0,
            inputs: &mut inputs,
        };

        let state = exec_and_wait_inner(&mut req, config, outdir).await;
        let key = req.key;
        let params = req.params;
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

        save_exec_info(&exec_info, outdir).await?;
        let zip = zip_dir_into_bytes(outdir)?;
        let size = zip.len();
        tracing::info!("sending zip ({size} bytes)");
        Ok(ExecAndWaitResponse { zip })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::main_rocket;
    use rocket::http::{ContentType, Status};
    use rocket::local::blocking::Client;
    use rocket::serde::json::Json;

    fn extract_exec_info(resp: &[u8]) -> ExecInfo {
        let reader = std::io::Cursor::new(resp);
        let mut zip = zip::ZipArchive::new(reader).unwrap();
        let file = zip.by_name("exec_info.json").unwrap();
        serde_json::from_reader(file).unwrap()
    }

    fn ask_exec(req: &ExecAndWaitRequest) -> ExecInfo {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");

        let uri = uri!(super::http::exec_and_wait(
            demo_id = &req.demo_id,
            key = &req.key,
            ddl_run = &req.ddl_run,
            parameters = &req.params,
            timeout = req.timeout,
        ));

        let response = client.post(uri).header(ContentType::Form).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(response.content_type(), Some(ContentType::ZIP));
        let bytes = response.into_bytes().unwrap();
        extract_exec_info(&bytes)
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_exec_and_wait() {
        let req = ExecAndWaitRequest {
            demo_id: DemoID::try_from("t001").unwrap(),
            key: RunKey::try_from("test_exec_and_wait").unwrap(),
            ddl_run: "test $z = $IPOL_DEMOID".into(),
            params: RunParams::from([
                ("x".into(), ParamValue::PosInt(1)),
                ("y".into(), ParamValue::Float(2.5)),
                ("z".into(), ParamValue::String("t001".into())),
                ("a".into(), ParamValue::Bool(true)),
                ("b".into(), ParamValue::NegInt(-2)),
                ("param space".into(), ParamValue::String("hi world".into())),
            ]),
            timeout: Some(10),
            inputs: &mut [],
        };

        let exec_info = ask_exec(&req);
        assert_eq!(exec_info.status, "OK");
        assert_eq!(exec_info.key, req.key);
        assert_eq!(exec_info.params, req.params);
        assert_eq!(exec_info.error, None);
        assert_eq!(exec_info.algo_info.error_message, None);
        assert!(exec_info.algo_info.run_time.is_some());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_exec_and_wait_non_zero_exit_code() {
        let req = ExecAndWaitRequest {
            demo_id: DemoID::try_from("t001").unwrap(),
            key: RunKey::try_from("test_exec_and_wait_non_zero_exit_code").unwrap(),
            ddl_run: "echo a; exit 5; echo b;".into(),
            params: RunParams::new(),
            timeout: Some(10),
            inputs: &mut [],
        };

        let exec_info = ask_exec(&req);
        assert_eq!(exec_info.status, "KO");
        assert_eq!(exec_info.key, req.key);
        assert_eq!(exec_info.params, req.params);
        assert_eq!(exec_info.error, Some("Non-zero exit code (5): a\n".into()));
        assert_eq!(
            exec_info.algo_info.error_message,
            Some("Non-zero exit code (5): a\n".into())
        );
        assert!(exec_info.algo_info.run_time.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_exec_and_wait_timeout() {
        let req = ExecAndWaitRequest {
            demo_id: DemoID::try_from("t001").unwrap(),
            key: RunKey::try_from("test_exec_and_wait_timeout").unwrap(),
            ddl_run: "sleep 2".into(),
            params: RunParams::new(),
            timeout: Some(1),
            inputs: &mut [],
        };

        let exec_info = ask_exec(&req);
        assert_eq!(exec_info.status, "KO");
        assert_eq!(exec_info.key, req.key);
        assert_eq!(exec_info.params, req.params);
        assert_eq!(exec_info.error, Some("IPOLTimeoutError".into()));
        assert_eq!(
            exec_info.algo_info.error_message,
            Some("IPOLTimeoutError: Execution timeout".into())
        );
        assert!(exec_info.algo_info.run_time.is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_exec_and_wait_run_time() {
        let req = ExecAndWaitRequest {
            demo_id: DemoID::try_from("t001").unwrap(),
            key: RunKey::try_from("test_exec_and_wait_run_time").unwrap(),
            ddl_run: "sleep 2".into(),
            params: RunParams::new(),
            timeout: Some(10),
            inputs: &mut [],
        };

        let exec_info = ask_exec(&req);
        assert_eq!(exec_info.status, "OK");
        assert_eq!(exec_info.key, req.key);
        assert_eq!(exec_info.params, req.params);
        assert_eq!(exec_info.error, None);
        assert_eq!(exec_info.algo_info.error_message, None);
        assert!(exec_info.algo_info.run_time > Some(1.5));
    }
}
