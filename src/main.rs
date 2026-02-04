use anyhow::{anyhow, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process::Command, sync::Arc};

#[derive(Clone)]
struct AppState {
    github_repo: String,
    bearer_token: String,
    repo_path: PathBuf,
    github_owner: String,
    github_repo_name: String,
    min_tag_age_hours: i64,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct CheckoutRequest {
    tag: String,
}

#[derive(Deserialize)]
struct GitHubRef {
    object: GitHubObject,
}

#[derive(Deserialize)]
struct GitHubObject {
    sha: String,
    #[serde(rename = "type")]
    object_type: String,
}

#[derive(Deserialize)]
struct GitHubTag {
    object: GitHubTagObject,
}

#[derive(Deserialize)]
struct GitHubTagObject {
    sha: String,
}

#[derive(Deserialize)]
struct GitHubCommit {
    commit: GitHubCommitInfo,
}

#[derive(Deserialize)]
struct GitHubCommitInfo {
    committer: GitHubCommitter,
}

#[derive(Deserialize)]
struct GitHubCommitter {
    date: DateTime<Utc>,
}

fn parse_github_url(url: &str) -> Result<(String, String)> {
    let url = url
        .trim_end_matches('/')
        .trim_end_matches(".git");

    let parts: Vec<&str> = url.split('/').collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid GitHub URL format"));
    }

    let repo = parts[parts.len() - 1].to_string();
    let owner = parts[parts.len() - 2].to_string();

    Ok((owner, repo))
}

fn verify_bearer_token(headers: &HeaderMap, expected: &str) -> Result<(), (StatusCode, Json<StatusResponse>)> {
    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(StatusResponse {
                    status: "error".to_string(),
                    tag: None,
                    error: Some("Missing Authorization header".to_string()),
                }),
            )
        })?;

    let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(StatusResponse {
                status: "error".to_string(),
                tag: None,
                error: Some("Invalid Authorization header format".to_string()),
            }),
        )
    })?;

    if token != expected {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(StatusResponse {
                status: "error".to_string(),
                tag: None,
                error: Some("Invalid token".to_string()),
            }),
        ));
    }

    Ok(())
}

async fn compose_up(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    match run_docker_compose(&state.repo_path, &["up", "-d"]) {
        Ok(_) => (
            StatusCode::OK,
            Json(StatusResponse {
                status: "ok".to_string(),
                tag: None,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(StatusResponse {
                status: "error".to_string(),
                tag: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

async fn compose_down(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    match run_docker_compose(&state.repo_path, &["down"]) {
        Ok(_) => (
            StatusCode::OK,
            Json(StatusResponse {
                status: "ok".to_string(),
                tag: None,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(StatusResponse {
                status: "error".to_string(),
                tag: None,
                error: Some(e.to_string()),
            }),
        ),
    }
}

async fn git_checkout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CheckoutRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer_token(&headers, &state.bearer_token) {
        return e;
    }

    match do_git_checkout(&state, &payload.tag).await {
        Ok(_) => (
            StatusCode::OK,
            Json(StatusResponse {
                status: "ok".to_string(),
                tag: Some(payload.tag),
                error: None,
            }),
        ),
        Err(e) => {
            let (status, msg) = categorize_error(&e);
            (
                status,
                Json(StatusResponse {
                    status: "error".to_string(),
                    tag: None,
                    error: Some(msg),
                }),
            )
        }
    }
}

fn categorize_error(e: &anyhow::Error) -> (StatusCode, String) {
    let msg = e.to_string();
    if msg.contains("tag too recent") || msg.contains("not found") {
        (StatusCode::BAD_REQUEST, msg)
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}

async fn do_git_checkout(state: &AppState, tag: &str) -> Result<()> {
    // Clone or fetch the repository
    if state.repo_path.exists() {
        run_git(&state.repo_path, &["fetch", "--tags", "--force"])
            .context("Failed to fetch repository")?;
    } else {
        run_git_clone(&state.github_repo, &state.repo_path)
            .context("Failed to clone repository")?;
    }

    // Get commit SHA for the tag via GitHub API
    let commit_sha = get_tag_commit_sha(&state.github_owner, &state.github_repo_name, tag).await?;

    // Get commit date via GitHub API
    let commit_date = get_commit_date(&state.github_owner, &state.github_repo_name, &commit_sha).await?;

    // Check if tag is at least min_tag_age_hours old
    let min_age = Utc::now() - chrono::Duration::hours(state.min_tag_age_hours);
    if commit_date > min_age {
        return Err(anyhow!("tag too recent: commit date {} is less than {} hours old", commit_date, state.min_tag_age_hours));
    }

    // Checkout the tag
    run_git(&state.repo_path, &["checkout", tag])
        .context("Failed to checkout tag")?;

    Ok(())
}

async fn get_tag_commit_sha(owner: &str, repo: &str, tag: &str) -> Result<String> {
    let client = reqwest::Client::new();

    // First, get the ref for the tag
    let ref_url = format!(
        "https://api.github.com/repos/{}/{}/git/refs/tags/{}",
        owner, repo, tag
    );

    let response = client
        .get(&ref_url)
        .header("User-Agent", "compose-manager")
        .send()
        .await
        .context("Failed to fetch tag ref from GitHub")?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(anyhow!("tag not found: {}", tag));
    }

    let git_ref: GitHubRef = response
        .json()
        .await
        .context("Failed to parse GitHub ref response")?;

    // If it's an annotated tag, we need to dereference it to get the commit
    if git_ref.object.object_type == "tag" {
        let tag_url = format!(
            "https://api.github.com/repos/{}/{}/git/tags/{}",
            owner, repo, git_ref.object.sha
        );

        let tag_response = client
            .get(&tag_url)
            .header("User-Agent", "compose-manager")
            .send()
            .await
            .context("Failed to fetch tag object from GitHub")?;

        let tag_obj: GitHubTag = tag_response
            .json()
            .await
            .context("Failed to parse GitHub tag response")?;

        Ok(tag_obj.object.sha)
    } else {
        // Lightweight tag, points directly to commit
        Ok(git_ref.object.sha)
    }
}

async fn get_commit_date(owner: &str, repo: &str, sha: &str) -> Result<DateTime<Utc>> {
    let client = reqwest::Client::new();

    let commit_url = format!(
        "https://api.github.com/repos/{}/{}/commits/{}",
        owner, repo, sha
    );

    let response = client
        .get(&commit_url)
        .header("User-Agent", "compose-manager")
        .send()
        .await
        .context("Failed to fetch commit from GitHub")?;

    let commit: GitHubCommit = response
        .json()
        .await
        .context("Failed to parse GitHub commit response")?;

    Ok(commit.commit.committer.date)
}

fn run_docker_compose(repo_path: &PathBuf, args: &[&str]) -> Result<String> {
    let mut cmd_args = vec!["compose"];
    cmd_args.extend(args);

    let output = Command::new("docker")
        .args(&cmd_args)
        .current_dir(repo_path)
        .output()
        .context("Failed to execute docker compose")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("docker compose failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_git(repo_path: &PathBuf, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .context("Failed to execute git command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git command failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_git_clone(repo_url: &str, dest: &PathBuf) -> Result<String> {
    let output = Command::new("git")
        .args(["clone", repo_url, dest.to_str().unwrap()])
        .output()
        .context("Failed to execute git clone")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git clone failed: {}", stderr));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let github_repo = std::env::var("GITHUB_REPO")
        .context("GITHUB_REPO environment variable is required")?;

    let bearer_token = std::env::var("BEARER_TOKEN")
        .context("BEARER_TOKEN environment variable is required")?;

    let repo_path = std::env::var("REPO_PATH")
        .unwrap_or_else(|_| "/app/repo".to_string());

    let min_tag_age_hours: i64 = std::env::var("MIN_TAG_AGE_HOURS")
        .unwrap_or_else(|_| "48".to_string())
        .parse()
        .context("MIN_TAG_AGE_HOURS must be a valid integer")?;

    let (github_owner, github_repo_name) = parse_github_url(&github_repo)
        .context("Failed to parse GITHUB_REPO URL")?;

    let state = Arc::new(AppState {
        github_repo,
        bearer_token,
        repo_path: PathBuf::from(repo_path),
        github_owner,
        github_repo_name,
        min_tag_age_hours,
    });

    let app = Router::new()
        .route("/compose/up", post(compose_up))
        .route("/compose/down", post(compose_down))
        .route("/git/checkout", post(git_checkout))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Server listening on port 8080");
    axum::serve(listener, app).await?;

    Ok(())
}
