//! Blocking REST client used by the terminal UI. Reqwest handles HTTPS,
//! chunked transfer encoding, IPv6 URLs, and team-mode bearer authentication.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::{Client, RequestBuilder, Response};

#[derive(Clone)]
pub struct ApiClient {
    base: String,
    token: Option<String>,
    client: Client,
    stream_client: Client,
}

impl ApiClient {
    pub fn new(base: String, token: Option<String>) -> Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        reqwest::Url::parse(&base).context("invalid API URL")?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()?;
        let stream_client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        Ok(Self {
            base,
            token,
            client,
            stream_client,
        })
    }

    fn request(&self, method: reqwest::Method, path: &str) -> RequestBuilder {
        let request = self
            .client
            .request(method, format!("{}{}", self.base, path));
        match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    fn checked(response: Response, path: &str) -> Result<Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        let detail = response.text().unwrap_or_default();
        bail!("HTTP {status} for {path}: {detail}")
    }

    pub fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(Self::checked(self.request(reqwest::Method::GET, path).send()?, path)?.json()?)
    }

    pub fn post_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        Ok(Self::checked(
            self.request(reqwest::Method::POST, path)
                .json(&serde_json::json!({}))
                .send()?,
            path,
        )?
        .json()?)
    }

    pub fn post_body(&self, path: &str, body: &str) -> Result<Vec<u8>> {
        Ok(Self::checked(
            self.request(reqwest::Method::POST, path)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string())
                .send()?,
            path,
        )?
        .bytes()?
        .to_vec())
    }

    pub fn post(&self, path: &str) -> Result<Vec<u8>> {
        self.post_body(path, "{}")
    }

    pub fn stream(&self, path: &str) -> Result<Response> {
        let request = self
            .stream_client
            .request(reqwest::Method::GET, format!("{}{}", self.base, path));
        let request = match &self.token {
            Some(token) => request.bearer_auth(token),
            None => request,
        };
        Self::checked(
            request
                .header(reqwest::header::ACCEPT, "text/event-stream")
                .send()?,
            path,
        )
    }
}
