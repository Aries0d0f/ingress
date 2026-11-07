// --- Social Redirects ---
// /s/<brand>[.tld][/path] → that profile, with a GA4 hit fired alongside.

use worker::{Context, Env, Headers, Request, Response, Result};

use crate::ga4::{self, Redirect};
use crate::matchers::SocialTarget;

pub async fn handle(
    req: &Request,
    env: &Env,
    ctx: &Context,
    target: SocialTarget<'_>,
    client_ip: Option<&str>,
) -> Result<Response> {
    let SocialTarget {
        at_mark,
        brand,
        tld,
        path,
    } = target;
    let destination = format!(
        "https://{brand}{tld}{path}/{}aries0d0f",
        if at_mark { "@" } else { "" }
    );

    let (client_id, minted_cookie) = ga4::resolve_client_id(req, client_ip);
    ga4::report_social_redirect(
        req,
        env,
        ctx,
        Redirect {
            brand,
            tld: &tld[1..],
            path: if path.is_empty() { "/" } else { path },
            target: &destination,
            client_id: &client_id,
            client_ip,
        },
    );

    let headers = Headers::new();
    headers.set("Location", &destination)?;
    if let Some(cookie) = minted_cookie {
        headers.append("Set-Cookie", &cookie)?;
    }

    Ok(Response::empty()?.with_status(301).with_headers(headers))
}
