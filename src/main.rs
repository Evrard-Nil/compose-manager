use anyhow::{anyhow, Context, Result};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use futures::stream::Stream;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    process::Command,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command as AsyncCommand,
    sync::RwLock,
};
use tracing::{error, info};

// --- Application State ---

struct AppState {
    bearer_token: String,
    github_owner: String,
    github_repo_name: String,
    min_tag_age_hours: i64,
    work_dir: PathBuf,
    env_files: Vec<String>,
    deployed_tag: RwLock<Option<String>>,
    http: reqwest::Client,
}

// --- API Types ---

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

type ApiResult = (StatusCode, Json<StatusResponse>);

fn ok(tag: Option<String>) -> ApiResult {
    (StatusCode::OK, Json(StatusResponse { status: "ok".into(), tag, output: None, error: None }))
}

fn ok_output(output: String) -> ApiResult {
    (StatusCode::OK, Json(StatusResponse { status: "ok".into(), tag: None, output: Some(output), error: None }))
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiResult {
    (code, Json(StatusResponse { status: "error".into(), tag: None, output: None, error: Some(msg.into()) }))
}

fn err_response(code: StatusCode, msg: impl Into<String>) -> Response {
    let body = serde_json::to_string(&StatusResponse {
        status: "error".into(),
        tag: None,
        output: None,
        error: Some(msg.into()),
    })
    .unwrap();
    Response::builder()
        .status(code)
        .header("Content-Type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

#[derive(Deserialize)]
struct ComposeRequest {
    tag: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default)]
    force_recreate: bool,
}

#[derive(Deserialize)]
struct ComposeDownRequest {
    tag: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    volumes: bool,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

#[derive(Deserialize)]
struct CleanRequest {
    #[serde(default)]
    volumes: bool,
    #[serde(default)]
    images: bool,
}

#[derive(Deserialize, Default)]
struct LogsRequest {
    #[serde(default)]
    file: Option<String>,
    #[serde(default = "default_tail")]
    tail: u32,
    #[serde(default)]
    services: Vec<String>,
}

fn default_tail() -> u32 {
    100
}

#[derive(Deserialize)]
struct RestartRequest {
    container: String,
}

// --- Env var validation ---

fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn validate_env_vars(env: &HashMap<String, String>) -> Result<(), String> {
    for (key, value) in env {
        if !is_valid_env_key(key) {
            return Err(format!("invalid env var key: '{}' (must match [A-Za-z_][A-Za-z0-9_]*)", key));
        }
        if value.contains('\n') || value.contains('\r') {
            return Err(format!("env var '{}' value must not contain newlines", key));
        }
    }
    Ok(())
}

fn write_temp_env_file(work_dir: &Path, env: &HashMap<String, String>) -> Result<PathBuf> {
    let path = work_dir.join(".env.tmp");
    let content: String = env
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, content).context("Failed to write temp env file")?;
    Ok(path)
}

// --- GitHub ---

#[derive(Deserialize)]
struct GitHubCommit {
    commit: GitHubCommitDetail,
}

#[derive(Deserialize)]
struct GitHubCommitDetail {
    committer: GitHubCommitter,
}

#[derive(Deserialize)]
struct GitHubCommitter {
    date: DateTime<Utc>,
}

async fn get_tag_commit_date(state: &AppState, tag: &str) -> Result<DateTime<Utc>> {
    let url = format!(
        "https://api.github.com/repos/{}/{}/commits/{}",
        state.github_owner, state.github_repo_name, tag
    );

    let resp = state.http.get(&url)
        .header("User-Agent", "compose-manager")
        .send().await
        .context("Failed to query GitHub API")?;

    if !resp.status().is_success() {
        return Err(anyhow!("tag not found: {}", tag));
    }

    let commit: GitHubCommit = resp.json().await
        .context("Failed to parse GitHub response")?;

    Ok(commit.commit.committer.date)
}

async fn validate_tag(state: &AppState, tag: &str) -> Result<(), (StatusCode, String)> {
    let commit_date = get_tag_commit_date(state, tag).await.map_err(|e| {
        let code = if e.to_string().contains("not found") {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (code, e.to_string())
    })?;

    let min_age = Utc::now() - chrono::Duration::hours(state.min_tag_age_hours);
    if commit_date > min_age {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("tag too recent: {} is less than {} hours old", commit_date, state.min_tag_age_hours),
        ));
    }

    Ok(())
}

async fn fetch_github_file(state: &AppState, tag: &str, path: &str) -> Result<String> {
    let url = format!(
        "https://raw.githubusercontent.com/{}/{}/{}/{}",
        state.github_owner, state.github_repo_name, tag, path
    );

    let resp = state.http.get(&url)
        .send().await
        .context("Failed to fetch file from GitHub")?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow!("file '{}' not found at tag '{}'", path, tag));
    }

    resp.text().await.context("Failed to read file content")
}

// --- Auth ---

fn verify_bearer_token(headers: &HeaderMap, expected: &str) -> Result<(), ApiResult> {
    let token = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header"))?;

    if token != expected {
        return Err(err(StatusCode::UNAUTHORIZED, "Invalid token"));
    }

    Ok(())
}

fn verify_bearer_token_raw(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, String)> {
    let token = headers.get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header".to_string()))?;

    if token != expected {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token".to_string()));
    }

    Ok(())
}

// --- NDJSON Streaming ---

#[derive(Serialize)]
struct NdjsonEvent {
    event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    success: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

struct NdjsonStream {
    stdout: Option<tokio::io::Lines<BufReader<tokio::process::ChildStdout>>>,
    stderr: Option<tokio::io::Lines<BufReader<tokio::process::ChildStderr>>>,
    wait_fut: Option<Pin<Box<dyn Future<Output = std::io::Result<std::process::ExitStatus>> + Send>>>,
    pending_commands: VecDeque<AsyncCommand>,
    temp_env_file: Option<PathBuf>,
    done: bool,
}

impl Stream for NdjsonStream {
    type Item = Result<String, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if this.done {
            return Poll::Ready(None);
        }

        // Poll stderr first
        if let Some(ref mut stderr) = this.stderr {
            match Pin::new(stderr).poll_next_line(cx) {
                Poll::Ready(Ok(Some(line))) => {
                    let event = NdjsonEvent {
                        event: "stderr".into(),
                        data: Some(line),
                        success: None,
                        exit_code: None,
                    };
                    let mut json = serde_json::to_string(&event).unwrap();
                    json.push('\n');
                    return Poll::Ready(Some(Ok(json)));
                }
                Poll::Ready(Ok(None)) => {
                    this.stderr = None;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => {}
            }
        }

        // Poll stdout
        if let Some(ref mut stdout) = this.stdout {
            match Pin::new(stdout).poll_next_line(cx) {
                Poll::Ready(Ok(Some(line))) => {
                    let event = NdjsonEvent {
                        event: "stdout".into(),
                        data: Some(line),
                        success: None,
                        exit_code: None,
                    };
                    let mut json = serde_json::to_string(&event).unwrap();
                    json.push('\n');
                    return Poll::Ready(Some(Ok(json)));
                }
                Poll::Ready(Ok(None)) => {
                    this.stdout = None;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => {}
            }
        }

        // If both streams are done, wait for child exit
        if this.stdout.is_none() && this.stderr.is_none() {
            if let Some(ref mut fut) = this.wait_fut {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(Ok(status)) => {
                        this.wait_fut = None;

                        // If successful and more commands pending, start next
                        if status.success() {
                            if let Some(mut next_cmd) = this.pending_commands.pop_front() {
                                match next_cmd.spawn() {
                                    Ok(mut child) => {
                                        this.stdout = child.stdout.take().map(|s| BufReader::new(s).lines());
                                        this.stderr = child.stderr.take().map(|s| BufReader::new(s).lines());
                                        this.wait_fut = Some(Box::pin(async move {
                                            let mut child = child;
                                            child.wait().await
                                        }));
                                        cx.waker().wake_by_ref();
                                        return Poll::Pending;
                                    }
                                    Err(e) => {
                                        this.done = true;
                                        if let Some(ref path) = this.temp_env_file {
                                            let _ = std::fs::remove_file(path);
                                        }
                                        return Poll::Ready(Some(Err(e)));
                                    }
                                }
                            }
                        }

                        this.done = true;

                        // Clean up temp env file
                        if let Some(ref path) = this.temp_env_file {
                            let _ = std::fs::remove_file(path);
                        }

                        let event = NdjsonEvent {
                            event: "done".into(),
                            data: None,
                            success: Some(status.success()),
                            exit_code: status.code(),
                        };
                        let mut json = serde_json::to_string(&event).unwrap();
                        json.push('\n');
                        return Poll::Ready(Some(Ok(json)));
                    }
                    Poll::Ready(Err(e)) => {
                        this.done = true;
                        if let Some(ref path) = this.temp_env_file {
                            let _ = std::fs::remove_file(path);
                        }
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => {}
                }
            } else {
                this.done = true;
                return Poll::Ready(None);
            }
        }

        Poll::Pending
    }
}

fn build_compose_cmd(
    work_dir: &Path,
    args: &[&str],
    file: &str,
    env_files: &[String],
    services: &[String],
    temp_env_file: Option<&Path>,
) -> AsyncCommand {
    let mut cmd = AsyncCommand::new("docker");
    cmd.args(["compose", "-f", file]);
    for ef in env_files {
        cmd.args(["--env-file", ef.as_str()]);
    }
    if let Some(tef) = temp_env_file {
        cmd.args(["--env-file", tef.to_str().unwrap()]);
    }
    cmd.args(args);
    for service in services {
        cmd.arg(service);
    }
    cmd.current_dir(work_dir);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd
}

fn stream_docker_compose_phased(
    work_dir: &Path,
    phases: &[&[&str]],
    file: &str,
    env_files: &[String],
    services: &[String],
    temp_env_file: Option<PathBuf>,
) -> Result<NdjsonStream> {
    let all_env_files: Vec<&str> = env_files.iter().map(|s| s.as_str())
        .chain(temp_env_file.as_ref().map(|p| p.to_str().unwrap()))
        .collect();

    info!(
        command = "docker compose",
        file = file,
        phases = ?phases,
        env_files = ?all_env_files,
        services = ?services,
        work_dir = %work_dir.display(),
        "Running streaming command"
    );

    let mut commands: VecDeque<AsyncCommand> = phases.iter()
        .map(|args| build_compose_cmd(work_dir, args, file, env_files, services, temp_env_file.as_deref()))
        .collect();

    let mut first_cmd = commands.pop_front()
        .ok_or_else(|| anyhow!("no command phases specified"))?;

    let mut child = first_cmd.spawn().with_context(|| {
        format!(
            "Failed to execute: docker compose -f {} (work_dir: {})",
            file,
            work_dir.display()
        )
    })?;

    let stdout = child.stdout.take().map(|s| BufReader::new(s).lines());
    let stderr = child.stderr.take().map(|s| BufReader::new(s).lines());
    let wait_fut: Pin<Box<dyn Future<Output = std::io::Result<std::process::ExitStatus>> + Send>> =
        Box::pin(async move {
            let mut child = child;
            child.wait().await
        });

    Ok(NdjsonStream {
        stdout,
        stderr,
        wait_fut: Some(wait_fut),
        pending_commands: commands,
        temp_env_file,
        done: false,
    })
}

fn stream_docker_compose(
    work_dir: &Path,
    args: &[&str],
    file: &str,
    env_files: &[String],
    services: &[String],
    temp_env_file: Option<PathBuf>,
) -> Result<NdjsonStream> {
    stream_docker_compose_phased(work_dir, &[args], file, env_files, services, temp_env_file)
}

// --- Handlers ---

async fn compose_up(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ComposeRequest>,
) -> Response {
    if let Err((code, msg)) = verify_bearer_token_raw(&headers, &state.bearer_token) {
        return err_response(code, msg);
    }

    if let Err((code, msg)) = validate_tag(&state, &payload.tag).await {
        return err_response(code, msg);
    }

    if !payload.env.is_empty() {
        if let Err(msg) = validate_env_vars(&payload.env) {
            return err_response(StatusCode::BAD_REQUEST, msg);
        }
    }

    let file = payload.file.unwrap_or_else(|| "docker-compose.yml".into());

    // Fetch compose file from GitHub and write to work directory
    let content = match fetch_github_file(&state, &payload.tag, &file).await {
        Ok(c) => c,
        Err(e) => return err_response(StatusCode::BAD_REQUEST, e.to_string()),
    };

    if let Err(e) = tokio::fs::create_dir_all(&state.work_dir).await {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create work dir: {}", e));
    }
    if let Err(e) = tokio::fs::write(state.work_dir.join(&file), &content).await {
        return err_response(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write file: {}", e));
    }

    let temp_env_file = if !payload.env.is_empty() {
        match write_temp_env_file(&state.work_dir, &payload.env) {
            Ok(p) => Some(p),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    } else {
        None
    };

    let mut up_args = vec!["up", "-d", "--remove-orphans"];
    if payload.force_recreate {
        up_args.push("--force-recreate");
    }

    let stream = match stream_docker_compose_phased(
        &state.work_dir,
        &[&["pull"], &up_args],
        &file,
        &state.env_files,
        &payload.services,
        temp_env_file,
    ) {
        Ok(s) => s,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    *state.deployed_tag.write().await = Some(payload.tag);

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-ndjson")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn compose_down(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<ComposeDownRequest>,
) -> Response {
    if let Err((code, msg)) = verify_bearer_token_raw(&headers, &state.bearer_token) {
        return err_response(code, msg);
    }

    if let Err((code, msg)) = validate_tag(&state, &payload.tag).await {
        return err_response(code, msg);
    }

    if !payload.env.is_empty() {
        if let Err(msg) = validate_env_vars(&payload.env) {
            return err_response(StatusCode::BAD_REQUEST, msg);
        }
    }

    let file = payload.file.unwrap_or_else(|| "docker-compose.yml".into());
    let mut args = vec!["down"];
    if payload.volumes {
        args.push("-v");
    }

    let temp_env_file = if !payload.env.is_empty() {
        match write_temp_env_file(&state.work_dir, &payload.env) {
            Ok(p) => Some(p),
            Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        }
    } else {
        None
    };

    let stream = match stream_docker_compose(
        &state.work_dir,
        &args,
        &file,
        &state.env_files,
        &payload.services,
        temp_env_file,
    ) {
        Ok(s) => s,
        Err(e) => return err_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-ndjson")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn compose_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<LogsRequest>>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    let (file, tail, services) = body
        .map(|b| (b.file.clone(), b.tail, b.services.clone()))
        .unwrap_or((None, default_tail(), vec![]));

    let file = file.unwrap_or_else(|| "docker-compose.yml".into());
    let tail_str = tail.to_string();

    match run_docker_compose(&state.work_dir, &["logs", "--tail", &tail_str], &file, &state.env_files, &services) {
        Ok(output) => ok_output(output),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn docker_ps(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    match run_command("docker", &["ps", "--format", "json"]) {
        Ok(output) => ok_output(output),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn docker_restart(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RestartRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    info!(command = "docker restart", container = %payload.container, "Running command");

    match run_command("docker", &["restart", &payload.container]) {
        Ok(_) => ok(None),
        Err(e) => {
            error!(command = "docker restart", container = %payload.container, error = %e, "Command failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        }
    }
}

async fn docker_clean(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CleanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    if !payload.volumes && !payload.images {
        return err(StatusCode::BAD_REQUEST, "At least one of 'volumes' or 'images' must be true");
    }

    match run_docker_prune(payload.volumes, payload.images) {
        Ok(_) => ok(None),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tag = state.deployed_tag.read().await.clone();
    ok(tag)
}

// --- Shell Commands ---

fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute: {} {}", program, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "{} {} failed (exit {}):\nstderr: {}\nstdout: {}",
            program,
            args.join(" "),
            output.status.code().map(|c| c.to_string()).unwrap_or("signal".into()),
            stderr,
            stdout
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_docker_compose(work_dir: &Path, args: &[&str], file: &str, env_files: &[String], services: &[String]) -> Result<String> {
    info!(command = "docker compose", file = file, args = ?args, env_files = ?env_files, services = ?services, work_dir = %work_dir.display(), "Running command");
    let mut cmd = Command::new("docker");
    cmd.args(["compose", "-f", file]);
    for env_file in env_files {
        cmd.args(["--env-file", env_file]);
    }
    cmd.args(args);
    for service in services {
        cmd.arg(service);
    }
    let output = cmd
        .current_dir(work_dir)
        .output()
        .with_context(|| format!(
            "Failed to execute: docker compose -f {} {} (work_dir: {})",
            file, args.join(" "), work_dir.display()
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        error!(file = file, args = ?args, exit_code = output.status.code(), %stderr, "Command failed");
        return Err(anyhow!(
            "docker compose failed (exit {}):\nstderr: {}\nstdout: {}",
            output.status.code().map(|c| c.to_string()).unwrap_or("signal".into()),
            stderr,
            stdout
        ));
    }

    info!(command = "docker compose", file = file, args = ?args, "Command completed successfully");
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_docker_prune(volumes: bool, images: bool) -> Result<String> {
    let mut output_text = String::new();

    if volumes {
        info!(command = "docker volume prune", "Running command");
        let result = run_command("docker", &["volume", "prune", "-f"])?;
        info!(command = "docker volume prune", "Command completed successfully");
        output_text.push_str(&result);
    }

    if images {
        info!(command = "docker image prune", "Running command");
        let result = run_command("docker", &["image", "prune", "-af"])?;
        info!(command = "docker image prune", "Command completed successfully");
        output_text.push_str(&result);
    }

    Ok(output_text)
}

// --- Main ---

fn parse_github_url(url: &str) -> Result<(String, String)> {
    let url = url.trim_end_matches('/').trim_end_matches(".git");
    let parts: Vec<&str> = url.split('/').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid GitHub URL format"));
    }
    Ok((parts[parts.len() - 2].to_string(), parts[parts.len() - 1].to_string()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let github_repo = std::env::var("GITHUB_REPO")
        .context("GITHUB_REPO environment variable is required")?;
    let bearer_token = std::env::var("BEARER_TOKEN")
        .context("BEARER_TOKEN environment variable is required")?;
    let work_dir = std::env::var("WORK_DIR")
        .unwrap_or_else(|_| "/app/work".to_string());
    let min_tag_age_hours: i64 = std::env::var("MIN_TAG_AGE_HOURS")
        .unwrap_or_else(|_| "48".to_string())
        .parse()
        .context("MIN_TAG_AGE_HOURS must be a valid integer")?;

    let env_files: Vec<String> = std::env::var("ENV_FILES")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let (github_owner, github_repo_name) = parse_github_url(&github_repo)?;

    let state = Arc::new(AppState {
        bearer_token,
        github_owner,
        github_repo_name,
        min_tag_age_hours,
        work_dir: PathBuf::from(work_dir),
        env_files,
        deployed_tag: RwLock::new(None),
        http: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/compose/up", post(compose_up))
        .route("/compose/down", post(compose_down))
        .route("/compose/logs", post(compose_logs))
        .route("/docker/clean", post(docker_clean))
        .route("/docker/ps", get(docker_ps))
        .route("/docker/restart", post(docker_restart))
        .route("/version", get(version))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Server listening on port 8080");
    axum::serve(listener, app).await?;

    Ok(())
}
