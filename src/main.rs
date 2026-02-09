use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command, sync::Arc};
use tokio::sync::RwLock;

// --- Application State ---

struct AppState {
    bearer_token: String,
    github_owner: String,
    github_repo_name: String,
    min_tag_age_hours: i64,
    work_dir: PathBuf,
    env_files: Vec<String>,
    current_tag: RwLock<Option<String>>,
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

#[derive(Deserialize)]
struct CheckoutRequest {
    tag: String,
}

#[derive(Deserialize, Default)]
struct ComposeRequest {
    #[serde(default)]
    file: Option<String>,
}

#[derive(Deserialize)]
struct ComposeDownRequest {
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    volumes: bool,
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
}

fn default_tail() -> u32 {
    100
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

// --- Handlers ---

async fn git_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CheckoutRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    let commit_date = match get_tag_commit_date(&state, &payload.tag).await {
        Ok(d) => d,
        Err(e) => {
            let code = if e.to_string().contains("not found") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return err(code, e.to_string());
        }
    };

    let min_age = Utc::now() - chrono::Duration::hours(state.min_tag_age_hours);
    if commit_date > min_age {
        return err(StatusCode::BAD_REQUEST, format!(
            "tag too recent: {} is less than {} hours old", commit_date, state.min_tag_age_hours
        ));
    }

    *state.current_tag.write().await = Some(payload.tag.clone());
    ok(Some(payload.tag))
}

async fn compose_up(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<ComposeRequest>>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    let tag = state.current_tag.read().await.clone();
    let Some(tag) = tag else {
        return err(StatusCode::BAD_REQUEST, "No tag set. Call /git/checkout first.");
    };

    let file = body.and_then(|b| b.file.clone()).unwrap_or_else(|| "docker-compose.yml".into());

    // Fetch compose file from GitHub and write to work directory
    let content = match fetch_github_file(&state, &tag, &file).await {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, e.to_string()),
    };

    if let Err(e) = tokio::fs::create_dir_all(&state.work_dir).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create work dir: {}", e));
    }
    if let Err(e) = tokio::fs::write(state.work_dir.join(&file), &content).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write file: {}", e));
    }

    match run_docker_compose(&state.work_dir, &["up", "-d"], &file, &state.env_files) {
        Ok(_) => {
            *state.deployed_tag.write().await = Some(tag);
            ok(None)
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn compose_down(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<ComposeDownRequest>>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    let (file, volumes) = body
        .map(|b| (b.file.clone(), b.volumes))
        .unwrap_or((None, false));

    let file = file.unwrap_or_else(|| "docker-compose.yml".into());
    let mut args = vec!["down"];
    if volumes { args.push("-v"); }

    match run_docker_compose(&state.work_dir, &args, &file, &state.env_files) {
        Ok(_) => ok(None),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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

async fn compose_logs(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Option<Json<LogsRequest>>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    let (file, tail) = body
        .map(|b| (b.file.clone(), b.tail))
        .unwrap_or((None, default_tail()));

    let file = file.unwrap_or_else(|| "docker-compose.yml".into());
    let tail_str = tail.to_string();

    match run_docker_compose(&state.work_dir, &["logs", "--tail", &tail_str], &file, &state.env_files) {
        Ok(output) => ok_output(output),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tag = state.deployed_tag.read().await.clone();
    ok(tag)
}

// --- Shell Commands ---

fn run_docker_compose(work_dir: &PathBuf, args: &[&str], file: &str, env_files: &[String]) -> Result<String> {
    let mut cmd = Command::new("docker");
    cmd.args(["compose", "-f", file]);
    for env_file in env_files {
        cmd.args(["--env-file", env_file]);
    }
    let output = cmd
        .args(args)
        .current_dir(work_dir)
        .output()
        .with_context(|| format!(
            "Failed to execute: docker compose -f {} {} (work_dir: {})",
            file, args.join(" "), work_dir.display()
        ))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "docker compose failed (exit {}):\nstderr: {}\nstdout: {}",
            output.status.code().map(|c| c.to_string()).unwrap_or("signal".into()),
            stderr,
            stdout
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_docker_prune(volumes: bool, images: bool) -> Result<String> {
    let mut output_text = String::new();

    if volumes {
        let output = Command::new("docker")
            .args(["volume", "prune", "-f"])
            .output()
            .context("Failed to execute: docker volume prune -f")?;
        if !output.status.success() {
            return Err(anyhow!(
                "docker volume prune failed (exit {}):\nstderr: {}\nstdout: {}",
                output.status.code().map(|c| c.to_string()).unwrap_or("signal".into()),
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        output_text.push_str(&String::from_utf8_lossy(&output.stdout));
    }

    if images {
        let output = Command::new("docker")
            .args(["image", "prune", "-af"])
            .output()
            .context("Failed to execute: docker image prune -af")?;
        if !output.status.success() {
            return Err(anyhow!(
                "docker image prune failed (exit {}):\nstderr: {}\nstdout: {}",
                output.status.code().map(|c| c.to_string()).unwrap_or("signal".into()),
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            ));
        }
        output_text.push_str(&String::from_utf8_lossy(&output.stdout));
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
        current_tag: RwLock::new(None),
        deployed_tag: RwLock::new(None),
        http: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/compose/up", post(compose_up))
        .route("/compose/down", post(compose_down))
        .route("/compose/logs", post(compose_logs))
        .route("/docker/clean", post(docker_clean))
        .route("/git/checkout", post(git_checkout))
        .route("/version", get(version))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server listening on port 8080");
    axum::serve(listener, app).await?;

    Ok(())
}
