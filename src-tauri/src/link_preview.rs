use std::sync::Arc;
use std::sync::LazyLock;
use std::time::Duration;

use base64::Engine as _;
use regex::Regex;
use reqwest::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, LOCATION};
use serde::Serialize;
use url::{Host, Url};
use uuid::Uuid;

use crate::message_content::NativeMessageLinkTarget;

const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_IMAGE_BYTES: usize = 1536 * 1024;
const MAX_REDIRECTS: usize = 4;

static META_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<meta\b[^>]*>").expect("valid metadata tag regex"));
static META_ATTRIBUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)([a-z_:][a-z0-9_:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))"#)
        .expect("valid metadata attribute regex")
});
static TITLE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<title\b[^>]*>(.*?)</title>").expect("valid title regex"));
static HTML_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<[^>]+>").expect("valid HTML tag regex"));
static PREVIEW_ISOLATION_USER: LazyLock<String> =
    LazyLock::new(|| format!("qorc-preview-{}", Uuid::new_v4().simple()));
static PUBLIC_WEB_TLS_CONFIG: LazyLock<Result<rustls::ClientConfig, ()>> = LazyLock::new(|| {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
});

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeLinkPreview {
    pub url: String,
    pub display_url: String,
    pub host: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_data_url: Option<String>,
}

fn valid_fetch_url(url: &Url) -> bool {
    if url.as_str().len() > 2048
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return false;
    }
    let domain = match url.host() {
        Some(Host::Domain(domain)) => domain.trim_end_matches('.').to_ascii_lowercase(),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) | None => return false,
    };
    if domain.is_empty()
        || domain.len() > 253
        || domain == "localhost"
        || domain.ends_with(".localhost")
        || domain.ends_with(".local")
        || domain.ends_with(".internal")
        || domain.ends_with(".home.arpa")
    {
        return false;
    }
    matches!(
        (url.scheme(), url.port_or_known_default()),
        ("http", Some(80)) | ("https", Some(443))
    )
}

fn decode_html_entities(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#34;", "\"")
        .replace("&#x22;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&amp;", "&")
}

fn clean_text(value: &str, max_chars: usize) -> Option<String> {
    let decoded = decode_html_entities(value);
    let without_tags = HTML_TAG_RE.replace_all(&decoded, " ");
    let normalized = without_tags
        .chars()
        .filter(|character| !character.is_control() || character.is_whitespace())
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.is_empty() {
        return None;
    }
    let mut characters = normalized.chars();
    let mut shortened = characters.by_ref().take(max_chars).collect::<String>();
    if characters.next().is_some() {
        shortened.push('…');
    }
    Some(shortened)
}

fn metadata_values(html: &str) -> Vec<(String, String)> {
    META_TAG_RE
        .find_iter(html)
        .filter_map(|tag| {
            let mut key = None;
            let mut content = None;
            for captures in META_ATTRIBUTE_RE.captures_iter(tag.as_str()) {
                let name = captures.get(1)?.as_str().to_ascii_lowercase();
                let value = captures
                    .get(2)
                    .or_else(|| captures.get(3))
                    .or_else(|| captures.get(4))?
                    .as_str();
                match name.as_str() {
                    "property" | "name" if key.is_none() => {
                        key = Some(value.trim().to_ascii_lowercase())
                    }
                    "content" if content.is_none() => content = Some(value.to_string()),
                    _ => {}
                }
            }
            Some((key?, content?))
        })
        .collect()
}

fn find_metadata<'a>(metadata: &'a [(String, String)], names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        metadata
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    })
}

async fn read_capped_body(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if body
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > max_bytes)
        {
            return Err(());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_capped_html_prefix(
    response: &mut reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, ()> {
    let mut body = Vec::with_capacity(max_bytes.min(64 * 1024));
    while body.len() < max_bytes {
        let Some(chunk) = response.chunk().await.map_err(|_| ())? else {
            break;
        };
        let remaining = max_bytes - body.len();
        let take = remaining.min(chunk.len());
        body.extend_from_slice(&chunk[..take]);
        if take < chunk.len() {
            break;
        }
    }
    if body.is_empty() { Err(()) } else { Ok(body) }
}

async fn get_with_redirects(
    client: &reqwest::Client,
    mut url: Url,
    accept: &'static str,
) -> Result<(reqwest::Response, Url), ()> {
    for _ in 0..=MAX_REDIRECTS {
        if !valid_fetch_url(&url) {
            return Err(());
        }
        let response = client
            .get(url.clone())
            .header(ACCEPT, accept)
            .header(CACHE_CONTROL, "no-store")
            .send()
            .await
            .map_err(|_| ())?;
        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or(())?;
            url = url.join(location).map_err(|_| ())?;
            continue;
        }
        if !response.status().is_success() {
            return Err(());
        }
        return Ok((response, url));
    }
    Err(())
}

fn detected_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

async fn fetch_image(client: &reqwest::Client, page_url: &Url, value: &str) -> Option<String> {
    let decoded = decode_html_entities(value);
    let image_url = page_url.join(decoded.trim()).ok()?;
    let (mut response, _) = get_with_redirects(client, image_url, "image/*")
        .await
        .ok()?;
    let declared_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    if !matches!(
        declared_type.as_str(),
        "image/png" | "image/jpeg" | "image/gif" | "image/webp"
    ) {
        return None;
    }
    let bytes = read_capped_body(&mut response, MAX_IMAGE_BYTES)
        .await
        .ok()?;
    let mime = detected_image_mime(&bytes)?;
    Some(format!(
        "data:{mime};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

pub async fn fetch_link_preview(
    target: NativeMessageLinkTarget,
    socks_port: u16,
) -> Result<NativeLinkPreview, ()> {
    let Ok(page_url) = Url::parse(&target.url) else {
        tracing::warn!(stage = "parse", "[LINK-PREVIEW] metadata transport failed");
        return Err(());
    };
    if !valid_fetch_url(&page_url) {
        tracing::warn!(stage = "policy", "[LINK-PREVIEW] metadata transport failed");
        return Err(());
    }
    let Ok(proxy) = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks_port}")) else {
        tracing::warn!(
            stage = "proxy-config",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    };
    let Ok(tls_config) = PUBLIC_WEB_TLS_CONFIG.as_ref() else {
        tracing::warn!(
            stage = "tls-config",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    };
    let Ok(client) = reqwest::Client::builder()
        .proxy(proxy.basic_auth(PREVIEW_ISOLATION_USER.as_str(), "isolate"))
        .use_preconfigured_tls(tls_config.clone())
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .user_agent("qorc Link Preview")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(18))
        .build()
    else {
        tracing::warn!(
            stage = "client-build",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    };
    let Ok((mut response, resolved_url)) = get_with_redirects(
        &client,
        page_url,
        "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    )
    .await
    else {
        tracing::warn!(
            stage = "page-request",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    };
    if response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().unwrap_or_default().trim();
            !media_type.eq_ignore_ascii_case("text/html")
                && !media_type.eq_ignore_ascii_case("application/xhtml+xml")
        })
    {
        tracing::warn!(
            stage = "content-type",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    }
    let Ok(body) = read_capped_html_prefix(&mut response, MAX_HTML_BYTES).await else {
        tracing::warn!(
            stage = "html-read",
            "[LINK-PREVIEW] metadata transport failed"
        );
        return Err(());
    };
    let html = String::from_utf8_lossy(&body);
    let metadata = metadata_values(&html);
    let title = find_metadata(&metadata, &["og:title", "twitter:title"])
        .and_then(|value| clean_text(value, 120))
        .or_else(|| {
            TITLE_RE
                .captures(&html)
                .and_then(|captures| captures.get(1))
                .and_then(|value| clean_text(value.as_str(), 120))
        });
    let description = find_metadata(
        &metadata,
        &["og:description", "twitter:description", "description"],
    )
    .and_then(|value| clean_text(value, 240));
    let mut image_data_url = None;
    if let Some(image) = find_metadata(
        &metadata,
        &["og:image:secure_url", "og:image", "twitter:image"],
    ) {
        if let Ok(fetched_image_data_url) = tokio::time::timeout(
            Duration::from_secs(5),
            fetch_image(&client, &resolved_url, image),
        )
        .await
        {
            image_data_url = fetched_image_data_url;
        }
    }
    Ok(NativeLinkPreview {
        url: target.url,
        display_url: target.display_url,
        host: target.host,
        title,
        description,
        image_data_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_open_graph_metadata_in_any_attribute_order() {
        let html = r#"
            <meta content="A useful page" property="og:title">
            <meta name='description' content='A concise &amp; safe description.'>
            <meta property="og:image" content="/preview.png">
        "#;
        let metadata = metadata_values(html);
        assert_eq!(
            find_metadata(&metadata, &["og:title"]),
            Some("A useful page")
        );
        assert_eq!(
            clean_text(
                find_metadata(&metadata, &["description"]).expect("description exists"),
                240
            )
            .as_deref(),
            Some("A concise & safe description.")
        );
        assert_eq!(
            find_metadata(&metadata, &["og:image"]),
            Some("/preview.png")
        );
    }

    #[test]
    fn refuses_local_and_literal_network_targets() {
        assert!(!valid_fetch_url(
            &Url::parse("http://localhost/").expect("URL parses")
        ));
        assert!(!valid_fetch_url(
            &Url::parse("http://127.0.0.1/").expect("URL parses")
        ));
        assert!(valid_fetch_url(
            &Url::parse("https://example.com/page").expect("URL parses")
        ));
    }
}
