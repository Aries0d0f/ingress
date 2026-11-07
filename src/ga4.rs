// --- GA4 Reporting ---
// Server-side Measurement Protocol reporting for social redirects.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use worker::{Context, Date, Env, Fetch, Headers, Method, Request, RequestInit, Url};

const GA4_ENDPOINT: &str = "https://www.google-analytics.com/mp/collect";
const GA_COOKIE_NAME: &str = "_ga";
const GA_COOKIE_MAX_AGE: u32 = 60 * 60 * 24 * 730; // ~2 years, GA's own default
const LOCAL_HOSTS: &[&str] = &["localhost", "127.0.0.1", "[::1]"];

pub struct Redirect<'a> {
    pub brand: &'a str,
    pub tld: &'a str,
    pub path: &'a str,
    pub target: &'a str,
    pub client_id: &'a str,
    pub client_ip: Option<&'a str>,
}

// UN M49 continent codes; subcontinent needs per-country data, so it's unset.
fn un_m49_continent(code: &str) -> Option<&'static str> {
    Some(match code {
        "AF" => "002",
        "AS" => "142",
        "EU" => "150",
        "NA" | "SA" => "019",
        "OC" => "009",
        _ => return None,
    })
}

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

fn credentials(env: &Env) -> Option<(String, String)> {
    let get = |name| {
        env.secret(name)
            .ok()
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty())
    };
    Some((get("GA4_MEASUREMENT_ID")?, get("GA4_API_SECRET")?))
}

// "GA1.1.123.456" -> "123.456"
fn parse_ga_cookie(value: &str) -> Option<&str> {
    let rest = value.strip_prefix("GA")?;
    let mut parts = rest.splitn(3, '.');
    let (v, d, id) = (parts.next()?, parts.next()?, parts.next()?);
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let (a, b) = id.split_once('.')?;

    (v.len() == 1 && d.len() == 1 && digits(v) && digits(d) && digits(a) && digits(b)).then_some(id)
}

fn read_cookie(req: &Request, name: &str) -> Option<String> {
    header(req, "Cookie")?.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

// Deterministic per IP+UA, so cookie-less repeats from the same device still match.
fn derive_device_client_id(client_ip: Option<&str>, ua: Option<&str>) -> String {
    let digest = Sha256::digest(format!("{}::{}", client_ip.unwrap_or(""), ua.unwrap_or("")));
    let word = |i: usize| u32::from_be_bytes(digest[i..i + 4].try_into().unwrap()) % 2147483647;
    format!("{}.{}", word(0), word(4))
}

/// Reuses the `_ga` client_id, or mints one plus its `Set-Cookie` value.
pub fn resolve_client_id(req: &Request, client_ip: Option<&str>) -> (String, Option<String>) {
    if let Some(id) = read_cookie(req, GA_COOKIE_NAME)
        .as_deref()
        .and_then(parse_ga_cookie)
    {
        return (id.to_string(), None);
    }

    let minted = derive_device_client_id(client_ip, header(req, "User-Agent").as_deref());
    let is_local = req
        .url()
        .ok()
        .and_then(|u| u.host_str().map(|h| LOCAL_HOSTS.contains(&h)))
        .unwrap_or(false);
    let cookie = format!(
        "{GA_COOKIE_NAME}=GA1.1.{minted}; Max-Age={GA_COOKIE_MAX_AGE}; Path=/; HttpOnly; SameSite=Lax{}",
        if is_local { "" } else { "; Secure" }
    );

    (minted, Some(cookie))
}

fn referral_source(referer: Option<&str>) -> (String, &'static str) {
    referer
        .and_then(|r| Url::parse(r).ok())
        .and_then(|u| u.host_str().map(str::to_string))
        .map(|host| (host, "referral"))
        .unwrap_or_else(|| ("(direct)".into(), "(none)"))
}

// "en-US,en;q=0.9,zh-TW;q=0.8" -> "en-us"
fn primary_language(accept_language: Option<&str>) -> Option<String> {
    accept_language
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
}

// woothee names differ from ua-parser-js; normalise the common ones.
fn os_name(os: &str) -> &str {
    match os {
        "Mac OSX" => "macOS",
        "iPhone" | "iPad" | "iPod" => "iOS",
        s if s.starts_with("Windows") => "Windows",
        s => s,
    }
}

fn device_category(ua: &str, category: &str) -> &'static str {
    let is_tablet = ua.contains("iPad")
        || ua.contains("Tablet")
        || (ua.contains("Android") && !ua.contains("Mobile"));
    match category {
        _ if is_tablet => "tablet",
        "smartphone" | "mobilephone" => "mobile",
        _ => "desktop",
    }
}

fn device_info(req: &Request) -> Value {
    let ua = header(req, "User-Agent").unwrap_or_default();
    let language = primary_language(header(req, "Accept-Language").as_deref());
    let known =
        |s: &str| (!s.is_empty() && s != woothee::woothee::VALUE_UNKNOWN).then(|| s.to_string());

    let Some(parsed) = woothee::parser::Parser::new().parse(&ua) else {
        return json!({ "category": device_category(&ua, ""), "language": language });
    };

    json!({
        "category": device_category(&ua, parsed.category),
        "language": language,
        "operating_system": known(parsed.os).map(|s| os_name(&s).to_string()),
        "operating_system_version": known(&parsed.os_version),
        "browser": known(parsed.name),
        "browser_version": known(&parsed.version),
    })
}

// JSON.stringify drops `undefined`; mirror that by pruning nulls.
fn prune_nulls(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.retain(|_, v| !v.is_null());
            map.values_mut().for_each(prune_nulls);
        }
        Value::Array(items) => items.iter_mut().for_each(prune_nulls),
        _ => {}
    }
}

pub fn report_social_redirect(req: &Request, env: &Env, ctx: &Context, data: Redirect<'_>) {
    // Skip if GA4 credentials are missing
    let Some((measurement_id, api_secret)) = credentials(env) else {
        return;
    };
    let Ok(mut endpoint) = Url::parse(GA4_ENDPOINT) else {
        return;
    };
    endpoint
        .query_pairs_mut()
        .append_pair("measurement_id", &measurement_id)
        .append_pair("api_secret", &api_secret);

    // Cloudflare already resolves the visitor's real geo per request.
    let geo = req.cf();
    let country = geo.and_then(|g| g.country());
    let referer = header(req, "Referer");
    let (source, medium) = referral_source(referer.as_deref());
    let session_id = (Date::now().as_millis() / 1000).to_string();
    let page_location = req.url().map(|u| u.to_string()).ok();

    let user_location = country.map(|country| {
        let region_id = geo
            .and_then(|g| g.region_code())
            .map(|r| format!("{country}-{r}"));
        json!({
            "country_id": country,
            "region_id": region_id,
            "city": geo.and_then(|g| g.city()),
            "continent_id": geo.and_then(|g| g.continent()).and_then(|c| un_m49_continent(&c)),
        })
    });

    let mut body = json!({
        "client_id": data.client_id,
        // MP fields, not headers: developers.google.com/analytics/devguides/collection/protocol/ga4/reference
        "device": device_info(req),
        "ip_override": data.client_ip,
        "user_location": user_location,
        "events": [
            // Sets source/medium for this session; must precede social_redirect.
            {
                "name": "campaign_details",
                "params": { "session_id": session_id, "source": source, "medium": medium }
            },
            {
                "name": "page_view",
                "params": {
                    "session_id": session_id,
                    "engagement_time_msec": 1,
                    "page_location": page_location,
                    "page_referrer": referer,
                    "page_title": format!("Social Redirect · {}.{}", data.brand, data.tld)
                }
            },
            {
                "name": "social_redirect",
                "params": {
                    "session_id": session_id,
                    "engagement_time_msec": 1,
                    "brand": data.brand,
                    "tld": data.tld,
                    "path": data.path,
                    "destination": data.target
                }
            }
        ]
    });
    prune_nulls(&mut body);

    let headers = Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));

    let Ok(request) = Request::new_with_init(endpoint.as_str(), &init) else {
        return;
    };

    // Analytics must never surface as an error on the redirect it's reporting.
    ctx.wait_until(async move {
        let _ = Fetch::Request(request).send().await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ga_cookie() {
        assert_eq!(parse_ga_cookie("GA1.1.123.456"), Some("123.456"));
        assert_eq!(parse_ga_cookie("GA1.2.1.2"), Some("1.2"));
        assert_eq!(parse_ga_cookie("GA1.1.123"), None);
        assert_eq!(parse_ga_cookie("GA1.1.123.456.7"), None);
        assert_eq!(parse_ga_cookie("GA12.1.1.2"), None);
    }

    #[test]
    fn client_id_is_stable() {
        let a = derive_device_client_id(Some("1.1.1.1"), Some("curl"));
        assert_eq!(a, derive_device_client_id(Some("1.1.1.1"), Some("curl")));
        assert_ne!(a, derive_device_client_id(Some("1.1.1.2"), Some("curl")));
        // Same value the old TS edge produced.
        assert_eq!(
            derive_device_client_id(Some("1.1.1.1"), Some("curl/8.7.1")),
            "367755745.1560727550"
        );
    }

    #[test]
    fn language() {
        assert_eq!(
            primary_language(Some("en-US,en;q=0.9")),
            Some("en-us".into())
        );
        assert_eq!(primary_language(Some("")), None);
    }
}
