// --- Request Matchers ---
// Hand-rolled matchers; keeps the regex crate out of the wasm.

const CLI_UA: &[&str] = &[
    "xh",
    "curl",
    "wget",
    "powershell",
    "httpie",
    "axios",
    "got",
    "python-requests",
    "http-client",
    "grpc-go",
    "unknown",
];

const NATIVE_UA: &[&str] = &[
    "msie",
    "webkit",
    "wkwebview",
    "safari",
    "edge",
    "chrome",
    "chromium",
    "firefox",
    "html",
    "khtml",
    "gecko",
    "anthropic-ai",
    "slurp",
    "spider",
    "bot",
    "crawler",
    "facebook",
    "meta",
    "externalagent",
    "whatsapp",
];

const IP_HOST: &str = "ip.aries0d0f.me";
const REPORT_WORDS: &[&str] = &["whois", "abuse", "geo"];

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    let lower = haystack.to_ascii_lowercase();
    needles.iter().any(|n| lower.contains(n))
}

pub fn is_cli_ua(ua: &str) -> bool {
    contains_any(ua, CLI_UA)
}

pub fn is_native_ua(ua: &str) -> bool {
    contains_any(ua, NATIVE_UA)
}

// `/<query>` the IP tool reads as a report query, e.g. /whois+geo.
fn is_report_path(path: &str) -> bool {
    let Some(seg) = path.strip_prefix('/') else {
        return false;
    };
    let is_query_char = |c: char| is_word(c) || "@#?=+".contains(c);

    !seg.is_empty() && seg.chars().all(is_query_char) && contains_any(seg, REPORT_WORDS)
}

// /^\/(whois|abuse|geo).?(whois|abuse|geo)?$/
fn is_report_alias(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    let Some(rest) = REPORT_WORDS.iter().find_map(|w| rest.strip_prefix(w)) else {
        return false;
    };
    let is_tail = |s: &str| s.is_empty() || REPORT_WORDS.contains(&s);

    if is_tail(rest) {
        return true;
    }
    let mut chars = rest.chars();
    matches!(chars.next(), Some(c) if c != '\n' && c != '\r') && is_tail(chars.as_str())
}

// Paths the IP tool owns in CLI mode; anything else stays with the site.
fn is_ip_path(path: &str) -> bool {
    path == "/" || path.starts_with("/ip") || is_report_path(path) || is_report_alias(path)
}

pub const IP_ORIGIN: &str = "https://ip.aries0d0f.me";

// Browser /ip[/rest] on the main host → path on the IP host; /ipv6 etc. land on `/`.
pub fn browser_ip_redirect<'a>(path: &'a str, host: &str, ua: &str) -> Option<&'a str> {
    if host == IP_HOST || !is_native_ua(ua) {
        return None;
    }
    let rest = path.strip_prefix("/ip")?;
    Some(if rest.starts_with('/') { rest } else { "/" })
}

// UA first: browsers only reach the IP tool via its host; CLI also via its paths.
pub fn is_ip_lookup(path: &str, host: &str, ua: &str) -> bool {
    if host == IP_HOST {
        return true;
    }
    if is_native_ua(ua) {
        return false;
    }
    if is_cli_ua(ua) {
        return is_ip_path(path);
    }
    // Other clients (Postman, Deno, ...) keep the old /ip* and report shortcuts.
    path.starts_with("/ip") || is_report_alias(path)
}

#[derive(Debug, PartialEq)]
pub struct SocialTarget<'a> {
    pub at_mark: bool,
    pub brand: &'a str,
    pub tld: &'a str,
    pub path: &'a str,
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

// Splits `s` into (leading \w+, rest); None when no word char leads.
fn take_word(s: &str) -> Option<(&str, &str)> {
    let end = s.find(|c| !is_word(c)).unwrap_or(s.len());
    (end > 0).then(|| s.split_at(end))
}

// Takes `<sep>\w+` off the front, if present.
fn take_prefixed(s: &str, sep: char) -> (Option<&str>, &str) {
    let Some(after) = s.strip_prefix(sep) else {
        return (None, s);
    };
    match take_word(after) {
        Some((word, rest)) => (Some(&s[..1 + word.len()]), rest),
        None => (None, s),
    }
}

// /^\/s\/(@?)(\w+)(\.\w+)?(\/\w+)?/
pub fn match_social(path: &str) -> Option<SocialTarget<'_>> {
    let rest = path.strip_prefix("/s/")?;
    let (at_mark, rest) = match rest.strip_prefix('@') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    let (brand, rest) = take_word(rest)?;
    let (tld, rest) = take_prefixed(rest, '.');
    let (sub, _) = take_prefixed(rest, '/');

    Some(SocialTarget {
        at_mark,
        brand,
        tld: tld.unwrap_or(".com"),
        path: sub.unwrap_or(""),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "aries0d0f.me";
    const BROWSER: &str = "Mozilla/5.0 AppleWebKit Safari";

    #[test]
    fn report_paths() {
        for p in [
            "/whois",
            "/geo",
            "/abuse",
            "/whois+geo",
            "/abuse+whois+geo",
            "/GEO",
        ] {
            assert!(is_report_path(p), "{p}");
        }
        for p in ["/", "/whoi", "/geo/x", "/x/geo", "/whois,geo", "/en"] {
            assert!(!is_report_path(p), "{p}");
        }
    }

    #[test]
    fn ip_host_wins() {
        assert!(is_ip_lookup("/", IP_HOST, BROWSER));
        assert!(is_ip_lookup("/anything", IP_HOST, "curl/8.7.1"));
    }

    #[test]
    fn browsers_stay_on_site() {
        for p in ["/", "/ip", "/geo", "/whois+geo"] {
            assert!(!is_ip_lookup(p, HOST, BROWSER), "{p}");
        }
    }

    #[test]
    fn cli_ip_paths() {
        for p in ["/", "/ip", "/ipv6", "/geo", "/abuse+whois+geo"] {
            assert!(is_ip_lookup(p, HOST, "curl/8.7.1"), "{p}");
        }
        assert!(is_ip_lookup("/", HOST, "Unknown"));
    }

    #[test]
    fn cli_site_paths() {
        for p in [
            "/robots.txt",
            "/sitemap.xml",
            "/en",
            "/zh-tw/llms.txt",
            "/api/game",
        ] {
            assert!(!is_ip_lookup(p, HOST, "curl/8.7.1"), "{p}");
        }
    }

    #[test]
    fn report_aliases() {
        for p in [
            "/whois",
            "/geo",
            "/whois+geo",
            "/geowhois",
            "/abuse,geo",
            "/geo-",
        ] {
            assert!(is_report_alias(p), "{p}");
        }
        for p in ["/", "/whoi", "/geo/x/y", "/geo--", "/x/geo", "/geo+abc"] {
            assert!(!is_report_alias(p), "{p}");
        }
    }

    #[test]
    fn other_clients_keep_shortcuts() {
        let ua = "PostmanRuntime/7.39.0";
        for p in ["/ip", "/ipv6", "/geo", "/whois,geo"] {
            assert!(is_ip_lookup(p, HOST, ua), "{p}");
        }
        for p in ["/", "/en", "/abuse+whois+geo"] {
            assert!(!is_ip_lookup(p, HOST, ua), "{p}");
        }
        assert!(is_ip_lookup("/geo", HOST, "Deno/2.0"));
    }

    #[test]
    fn browser_ip_redirects() {
        assert_eq!(browser_ip_redirect("/ip", HOST, BROWSER), Some("/"));
        assert_eq!(browser_ip_redirect("/ip/", HOST, BROWSER), Some("/"));
        assert_eq!(browser_ip_redirect("/ip/geo", HOST, BROWSER), Some("/geo"));
        assert_eq!(browser_ip_redirect("/ipv6", HOST, BROWSER), Some("/"));
        assert_eq!(browser_ip_redirect("/en", HOST, BROWSER), None);
        assert_eq!(browser_ip_redirect("/ip", IP_HOST, BROWSER), None);
        assert_eq!(browser_ip_redirect("/ip", HOST, "curl/8.7.1"), None);
        assert_eq!(
            browser_ip_redirect("/ip", HOST, "PostmanRuntime/7.39.0"),
            None
        );
    }

    #[test]
    fn cli_keeps_report_aliases() {
        assert!(is_ip_lookup("/whois,geo", HOST, "curl/8.7.1"));
    }

    #[test]
    fn social() {
        let t = |at_mark, brand, tld, path| {
            Some(SocialTarget {
                at_mark,
                brand,
                tld,
                path,
            })
        };
        assert_eq!(match_social("/s/github"), t(false, "github", ".com", ""));
        assert_eq!(match_social("/s/@medium"), t(true, "medium", ".com", ""));
        assert_eq!(match_social("/s/x.io/in"), t(false, "x", ".io", "/in"));
        assert_eq!(match_social("/s/x/in/more"), t(false, "x", ".com", "/in"));
        assert_eq!(match_social("/s/x./y"), t(false, "x", ".com", ""));
        assert_eq!(match_social("/s/"), None);
        assert_eq!(match_social("/s/@"), None);
        assert_eq!(match_social("/en/s/x"), None);
    }
}
