// --- Ingress ---
// Front door for aries0d0f.me: social redirects here, the rest via service bindings.

mod ga4;
mod matchers;
mod social;

use worker::{Context, Env, Request, Response, Result, Url, event};

const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

// Browsers only HTTPS redirect
fn https_redirect(req: &Request) -> Result<Option<Response>> {
    let mut url = req.url()?;
    let is_local = url.host_str().is_some_and(|h| LOCAL_HOSTS.contains(&h));

    if url.scheme() != "http"
        || is_local
        || header(req, "Upgrade-Insecure-Requests").as_deref() != Some("1")
    {
        return Ok(None);
    }

    let _ = url.set_scheme("https");
    Response::redirect_with_status(url, 308).map(Some)
}

// CVE-2026-111497 (Brotli OOB write): refuse compressed request bodies.
fn rejects_encoding(req: &Request) -> bool {
    header(req, "Content-Encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .is_some_and(|e| !e.is_empty() && e != "identity")
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    if let Some(redirect) = https_redirect(&req)? {
        return Ok(redirect);
    }
    if rejects_encoding(&req) {
        return Response::error("Unsupported Content-Encoding", 415);
    }

    let url = req.url()?;
    let path = url.path();

    let ua = header(&req, "User-Agent").unwrap_or_else(|| "Unknown".into());

    if let Some(target) = matchers::match_social(path) {
        let client_ip = header(&req, "CF-Connecting-IP");
        return social::handle(&req, &env, &ctx, target, client_ip.as_deref()).await;
    }

    let host = url.host_str().unwrap_or("");

    if let Some(ip_path) = matchers::browser_ip_redirect(path, host, &ua) {
        let mut target = Url::parse(matchers::IP_ORIGIN)?;
        target.set_path(ip_path);
        target.set_query(url.query());
        return Response::redirect_with_status(target, 308);
    }

    if matchers::is_ip_lookup(path, host, &ua) {
        return env.service("IP_LOOKUP")?.fetch_request(req).await;
    }

    env.service("SITE")?.fetch_request(req).await
}
