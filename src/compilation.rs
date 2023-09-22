use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bollard::auth::DockerCredentials;
use bollard::image::{ListImagesOptions, RemoveImageOptions};
use rocket::form::Form;
use rocket::http::hyper::Body;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::fs;
use rocket::tokio::io::AsyncWriteExt;
use rocket::{tokio, State};

use bollard::{image::BuildImageOptions, Docker};

use futures_util::stream::StreamExt;
use git2::Repository;
use secrecy::{ExposeSecret, SecretString};
use tar::Builder;

use crate::config;
use crate::model::*;

#[derive(Debug, Clone)]
struct PrivateSSHKey(SecretString);

impl From<String> for PrivateSSHKey {
    fn from(s: String) -> Self {
        Self(s.into())
    }
}

impl<'r> rocket::form::FromFormField<'r> for PrivateSSHKey {
    fn from_value(field: rocket::form::ValueField<'r>) -> rocket::form::Result<'r, Self> {
        Ok(Self(field.value.to_string().into()))
    }
}

#[derive(Debug, Clone, FromForm)]
struct SSHKeyPair {
    public: String,
    private: PrivateSSHKey,
}

impl SSHKeyPair {
    #[cfg(test)]
    fn from_path(path: &str) -> Result<Self, std::io::Error> {
        // TODO: use anyhow to add context
        // ex: .with_context("couldn't open the ssh key {}", pub_path)
        let public = std::fs::read_to_string(&format!("{path}.pub"))?;
        let private = std::fs::read_to_string(&path)?;
        Ok(Self {
            public,
            private: private.into(),
        })
    }
}

#[derive(Debug, FromForm)]
pub struct EnsureCompilationRequest {
    #[field(validate=validate_demoid())]
    demo_id: DemoID,
    ddl_build: Json<DDLBuild>,
    ssh_key: Option<SSHKeyPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnsureCompilationResponse {
    status: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    buildlog: Option<String>,
}

#[derive(Debug, thiserror::Error)]
enum CompilationError {
    #[error("Compilation error")]
    BuildError(String),
    #[error("ipol-demorunner/io: {0}")]
    IO(#[from] std::io::Error),
    #[error("ipol-demorunner/docker: {0}")]
    Docker(#[from] bollard::errors::Error),
    #[error("ipol-demorunner/git: {0}")]
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

// from https://docs.rs/git2/0.14.2/src/git2/repo.rs.html#328
fn update_submodules(repo: &git2::Repository) -> Result<(), git2::Error> {
    fn add_subrepos(repo: &Repository, list: &mut Vec<Repository>) -> Result<(), git2::Error> {
        for mut subm in repo.submodules()? {
            subm.update(true, None)?;
            list.push(subm.open()?);
        }
        Ok(())
    }

    let mut repos = Vec::new();
    add_subrepos(repo, &mut repos)?;
    while let Some(repo) = repos.pop() {
        add_subrepos(&repo, &mut repos)?;
    }
    Ok(())
}

#[derive(Default)]
struct GitFetcher {
    ssh_key_pair: Option<SSHKeyPair>,
}

impl GitFetcher {
    fn builder() -> GitFetcherBuilder {
        GitFetcherBuilder::default()
    }
}

#[derive(Default)]
struct GitFetcherBuilder {
    ssh_key: Option<SSHKeyPair>,
}

impl GitFetcherBuilder {
    fn build(self) -> Result<GitFetcher, CompilationError> {
        Ok(GitFetcher {
            ssh_key_pair: self.ssh_key,
        })
    }

    fn ssh_key(mut self, ssh_key: Option<SSHKeyPair>) -> Self {
        self.ssh_key = ssh_key;
        self
    }
}

#[tracing::instrument(skip(git_fetcher, url, rev))]
fn prepare_git(
    git_fetcher: &GitFetcher,
    path: &Path,
    url: &str,
    rev: &str,
) -> Result<String, CompilationError> {
    tracing::debug!("preparing the git folder {url}:{rev} to {path:?}");
    // NOTE: libgit2 does not support shallow fetches yet
    if let Some(current_url) = url_of_git_repository(path) {
        if current_url != url {
            tracing::debug!("the current url is different, removing {path:?}");
            std::fs::remove_dir_all(path)?;
        }
    } else if path.exists() {
        tracing::debug!("couldn't get the current url but the path exists, removing {path:?}");
        std::fs::remove_dir_all(path)?;
    }

    let get_fetch_options = || {
        let mut fo = git2::FetchOptions::default();

        if let Some(key_pair) = &git_fetcher.ssh_key_pair {
            let mut callbacks = git2::RemoteCallbacks::new();
            callbacks.credentials(move |_url, username_from_url, _allowed_types| {
                let ssh_pubkey = Some(key_pair.public.as_str());
                let ssh_key = &key_pair.private;
                match username_from_url {
                    Some(username) => git2::Cred::ssh_key_from_memory(username, ssh_pubkey, ssh_key.0.expose_secret(), None),
                    None => Err(git2::Error::from_str("git auth: couldn't parse the username from the url (make sure that the repository is public or that the url is formatted as such: 'https://<username>@...' or 'ssh://<username>@...')"))
                }
            });
            fo.remote_callbacks(callbacks);
        }

        fo.download_tags(git2::AutotagOption::All);
        fo
    };

    let repo = if path.exists() {
        Repository::open(path)?
    } else {
        tracing::debug!("cloning the repo");
        let fo = get_fetch_options();
        let mut builder = git2::build::RepoBuilder::new();
        builder.fetch_options(fo);
        builder.clone(url, path)?
    };

    {
        tracing::debug!("fetching origin");
        let mut fo = get_fetch_options();
        let mut remote = repo.find_remote("origin")?;
        remote.fetch::<&str>(&[], Some(&mut fo), None)?;
    }

    // TODO: support "master" as rev instead of "origin/master"?
    tracing::debug!("revparsing {rev}");
    let commit_id = repo.revparse_single(rev)?.peel_to_commit()?.id();
    repo.set_head_detached(commit_id)?;

    tracing::debug!("checking out {rev} = {commit_id}");
    let mut checkout = git2::build::CheckoutBuilder::new();
    checkout.force();
    repo.checkout_head(Some(&mut checkout))?;

    update_submodules(&repo)?;

    Ok(commit_id.to_string())
}

#[tracing::instrument(skip(req, config))]
async fn ensure_compilation_inner(
    req: Form<EnsureCompilationRequest>,
    config: &State<config::Config>,
) -> Result<(), CompilationError> {
    tracing::debug!("{req:?}");

    let compilation_path = PathBuf::from(&config.compilation_root).join(&req.demo_id);
    let srcdir = PathBuf::from(&compilation_path).join("src");
    let logfile = PathBuf::from(&compilation_path).join("build.log");
    fs::create_dir_all(&compilation_path).await?;
    let mut buildlog = fs::File::create(logfile).await?;

    let git_rev = {
        let srcdir = srcdir.clone();
        let ddl_build = req.ddl_build.clone();
        let git_fetcher = GitFetcher::builder().ssh_key(req.ssh_key.clone()).build()?;
        tokio::task::spawn_blocking(move || {
            prepare_git(&git_fetcher, &srcdir, &ddl_build.url, &ddl_build.rev)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))??
    };

    let dockerfile_path = PathBuf::from(&srcdir).join(&req.ddl_build.dockerfile);
    if !dockerfile_path.exists() {
        tracing::warn!("could not find the dockerfile at {dockerfile_path:?}");
        return Err(CompilationError::MissingDockerfile(
            req.ddl_build.dockerfile.clone(),
        ));
    }

    let docker = Docker::connect_with_socket_defaults()?.with_timeout(Duration::from_secs(60 * 10));

    let registry = config
        .registry_url
        .as_ref()
        .map_or(String::new(), |url| (url.clone() + "/"));

    let image_name = format!("{}{}{}", registry, config.docker_image_prefix, req.demo_id);
    let image_name_with_tag = format!("{}:{}", image_name, git_rev);

    let mut pulled = true;
    let mut stream = docker.create_image(
        Some(bollard::image::CreateImageOptions {
            from_image: image_name_with_tag.clone(),
            ..Default::default()
        }),
        None,
        None,
    );
    while let Some(msg) = stream.next().await {
        if msg.is_err() {
            pulled = false;
        }
    }

    if pulled {
        buildlog
            .write_all(
                format!(
                    "(docker image '{}' already exists (local or pulled))",
                    image_name_with_tag
                )
                .as_bytes(),
            )
            .await?;
        return Ok(());
    }

    let filters: HashMap<&str, Vec<&str>> =
        HashMap::from([("reference", vec![image_name.as_ref()])]);
    let current_images = docker
        .list_images(Some(ListImagesOptions {
            filters,
            ..Default::default()
        }))
        .await?;

    if current_images
        .iter()
        .any(|img| img.repo_tags.iter().any(|t| t == &image_name_with_tag))
    {
        tracing::debug!("docker image {image_name_with_tag} already exists, do not rebuild");
        buildlog
            .write_all(
                format!(
                    "(docker image '{}' already exists (local))",
                    image_name_with_tag
                )
                .as_bytes(),
            )
            .await?;
        return Ok(());
    }

    let build_image_options = BuildImageOptions {
        dockerfile: req.ddl_build.dockerfile.clone(),
        t: image_name_with_tag.clone(),
        q: false,
        rm: true,
        forcerm: true,
        ..Default::default()
    };

    let vec = {
        tracing::debug!("building the tar containing the source code");
        let srcdir = srcdir.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<u8>, CompilationError> {
            let mut ar = Builder::new(Vec::new());
            // respect the symlink of the source code (so keep symlinks as-is),
            // but also don't resolve symlinks on the host for obvious security reasons
            ar.follow_symlinks(false);
            // TODO: exclude .git
            ar.append_dir_all(".", srcdir)?;
            Ok(ar.into_inner()?)
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))??
    };
    let tar = Body::from(vec);

    let mut image_build_stream = docker.build_image(build_image_options, None, Some(tar));
    let mut buildlogbuf = String::new();
    let mut errored = false;
    while let Some(msg) = image_build_stream.next().await {
        let info = msg?;
        if let Some(stream) = info.stream {
            buildlog.write_all(stream.as_bytes()).await?;
            buildlogbuf.push_str(&stream);
        }
        if let Some(err) = info.error {
            buildlog.write_all(err.as_bytes()).await?;
            buildlogbuf.push_str(&err);
            errored = true;
        }
    }

    buildlog.flush().await?;

    if errored {
        // NOTE: this leaves a dangling image, which can be removed with `docker image prune`
        return Err(CompilationError::BuildError(buildlogbuf));
    }

    for image in current_images {
        let id = image.id;
        match docker
            .remove_image(
                &id,
                Some(RemoveImageOptions {
                    force: true,
                    ..Default::default()
                }),
                None,
            )
            .await
        {
            Ok(_) => {
                tracing::info!("removed old image {id}");
            }
            Err(err) => {
                tracing::error!("error while removing {id}: {err}");
            }
        }
    }

    if config.registry_url.is_some() {
        let creds = DockerCredentials {
            // we don't provide any authentification for now,
            // so we rely on a manual "docker login <registry_url>"
            serveraddress: config.registry_url.clone(),
            ..Default::default()
        };
        let push_options = Some(bollard::image::PushImageOptions { tag: git_rev });
        let mut stream = docker.push_image(&image_name, push_options, Some(creds));
        let mut pushlogbuf = String::new();
        while let Some(msg) = stream.next().await {
            let info = msg?;
            if let Some(stream) = info.progress {
                pushlogbuf.push_str(&stream);
            }
            if let Some(err) = info.error {
                pushlogbuf.push_str(&err);
                errored = true;
            }
        }

        if errored {
            warn!("compile/push: {}", pushlogbuf);
        }
    }

    Ok(())
}

#[post("/ensure_compilation", data = "<req>")]
pub async fn ensure_compilation(
    req: Form<EnsureCompilationRequest>,
    config: &State<config::Config>,
) -> Json<EnsureCompilationResponse> {
    let response = match ensure_compilation_inner(req, config).await {
        Ok(()) => EnsureCompilationResponse {
            status: "OK".into(),
            message: String::new(),
            buildlog: None,
        },
        Err(err) => match err {
            CompilationError::BuildError(ref buildlog) => EnsureCompilationResponse {
                status: "KO".into(),
                message: err.to_string(),
                buildlog: Some(buildlog.clone()),
            },
            _ => EnsureCompilationResponse {
                status: "KO".into(),
                message: err.to_string(),
                buildlog: None,
            },
        },
    };
    Json(response)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::main_rocket;
    use rocket::http::Status;
    use rocket::local::blocking::Client;

    use crate::test::GIT_URL;

    #[test]
    #[tracing_test::traced_test]
    fn test_ensure_compilation() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: GIT_URL.into(),
            rev: "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79".into(),
            dockerfile: ".ipol/Dockerfile".into(),
        };
        let response = client
            .post("/ensure_compilation")
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
                buildlog: None,
            })
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_ensure_compilation_missing_dockerfile() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: GIT_URL.into(),
            rev: "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79".into(),
            dockerfile: "missing".into(),
        };
        let response = client
            .post("/ensure_compilation")
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
                buildlog: None,
            })
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_ensure_compilation_invalid_git_commit() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: GIT_URL.into(),
            rev: "invalid".into(),
            dockerfile: ".ipol/Dockerfile".into(),
        };
        let response = client
            .post("/ensure_compilation")
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
                message: "ipol-demorunner/git: revspec 'invalid' not found; class=Reference (4); code=NotFound (-3)"
                    .into(),
                buildlog: None,
            })
        );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_ensure_compilation_invalid_dockerfile() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: GIT_URL.into(),
            rev: "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79".into(),
            dockerfile: "Makefile".into(),
        };
        let response = client
            .post("/ensure_compilation")
            .header(rocket::http::ContentType::Form)
            .body(format!(
                "demo_id={}&ddl_build={}",
                "t004",
                serde_json::to_string(&ddl_build).unwrap()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert_eq!(
            response.into_json(),
            Some(EnsureCompilationResponse {
                status: "KO".into(),
                message: "ipol-demorunner/docker: Docker responded with status code 400: dockerfile parse error line 1: unknown instruction: CFLAGS=".into(),
                buildlog: None,
            })
            );
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_ensure_compilation_build_error() {
        let client = Client::tracked(main_rocket()).expect("valid rocket instance");
        let ddl_build = DDLBuild {
            url: GIT_URL.into(),
            rev: "fe35687".into(),
            dockerfile: ".ipol/Dockerfile-error".into(),
        };
        let response = client
            .post("/ensure_compilation")
            .header(rocket::http::ContentType::Form)
            .body(format!(
                "demo_id={}&ddl_build={}",
                "t005",
                serde_json::to_string(&ddl_build).unwrap()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let r: EnsureCompilationResponse = response.into_json().unwrap();
        assert_eq!(r.status, "KO");
        assert_eq!(r.message, "Compilation error");
        assert!(!r.buildlog.unwrap().is_empty());
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_url_of_git_repository() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path();
        let url = url_of_git_repository(path);
        assert_eq!(url, None);

        let commit = "69b4dbc2ff9c3102c3b86639ed1ab608a6b5ba79";
        let url1 = String::from(GIT_URL);
        let git_fetcher = GitFetcher::default();
        let r = prepare_git(&git_fetcher, path, &url1, commit);
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), commit);

        let url = url_of_git_repository(path);
        assert_eq!(url, Some(url1));

        let url2 = format!("{}.git", GIT_URL);
        let r = prepare_git(&git_fetcher, path, &url2, commit);
        assert!(r.is_ok());
        assert_eq!(r.unwrap(), commit);

        let url = url_of_git_repository(path);
        assert_eq!(url, Some(url2));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_prepare_git_private() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path();

        let git_fetcher = GitFetcher::default();
        let ssh_key = SSHKeyPair::from_path("id_ed25519").ok();
        let git_fetcher_with_ssh = GitFetcher::builder().ssh_key(ssh_key).build().ok();

        let urls = std::env::var("PRIVATE_URLS").unwrap_or_default();
        for url in urls.split(',').filter(|x| !x.is_empty()) {
            dbg!(url);
            let is_ssh = url.contains("git@");

            let r = prepare_git(&git_fetcher, path, url, "master");
            dbg!(&r);
            assert_eq!(r.is_ok(), !is_ssh);

            if let Some(git_fetcher_with_ssh) = &git_fetcher_with_ssh {
                let r = prepare_git(git_fetcher_with_ssh, path, url, "master");
                dbg!(&r);
                assert!(r.is_ok());
            }
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_prepare_invalid_git() {
        let tmpdir = tempfile::tempdir().unwrap();
        let path = tmpdir.path();

        let git_fetcher = GitFetcher::default();
        let url = "https://github.com/kidanger/invalid-git";
        let r = prepare_git(&git_fetcher, path, url, "master");
        dbg!(&r);
        assert!(r.is_err());
    }
}
