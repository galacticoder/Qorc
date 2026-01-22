//! Link Commands

use tauri::State;
use serde::{Deserialize, Serialize};
use crate::state::AppState;

/// Link preview data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub site_name: Option<String>,
    pub favicon: Option<String>,
}

/// Fetch link preview via Tor
#[tauri::command]
pub async fn link_fetch_preview(
    url: String,
    state: State<'_, AppState>,
) -> Result<LinkPreview, String> {
    // Validate URL
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("Invalid URL protocol".to_string());
    }
    
    // Get Tor SOCKS port from state
    let tor = state.tor_manager()
        .ok_or_else(|| "Tor manager not initialized".to_string())?;
    
    if !tor.is_running() {
        return Err("Tor not running".to_string());
    }
    
    let socks_port = tor.get_socks_port();
    
    // Create client with SOCKS5 proxy
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("socks5://127.0.0.1:{}", socks_port))
            .map_err(|e| format!("Proxy error: {}", e))?)
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("Mozilla/5.0 (compatible; LinkPreview/1.0)")
        .build()
        .map_err(|e| format!("Client error: {}", e))?;
    
    // Fetch the page
    let response = client.get(&url).send().await
        .map_err(|e| format!("Request failed: {}", e))?;
    
    let html = response.text().await
        .map_err(|e| format!("Failed to read response: {}", e))?;
    
    // Parse Open Graph and meta tags
    let preview = parse_link_preview(&url, &html);
    
    Ok(preview)
}

/// Parse Open Graph and meta tags from HTML
fn parse_link_preview(url: &str, html: &str) -> LinkPreview {
    let document = scraper::Html::parse_document(html);
    
    let mut preview = LinkPreview {
        url: url.to_string(),
        title: None,
        description: None,
        image: None,
        site_name: None,
        favicon: None,
    };

    // Helper to get meta content
    let get_meta = |property: &str, is_property: bool| {
        let selector_str = if is_property {
            format!("meta[property='{}']", property)
        } else {
            format!("meta[name='{}']", property)
        };
        
        if let Ok(selector) = scraper::Selector::parse(&selector_str) {
            if let Some(element) = document.select(&selector).next() {
                return element.value().attr("content").map(|s| s.to_string());
            }
        }
        None
    };

    // Title: og:title -> <title>
    preview.title = get_meta("og:title", true);
    if preview.title.is_none() {
        if let Ok(selector) = scraper::Selector::parse("title") {
            if let Some(element) = document.select(&selector).next() {
                preview.title = Some(element.inner_html());
            }
        }
    }

    // Description: og:description -> meta description
    preview.description = get_meta("og:description", true);
    if preview.description.is_none() {
        preview.description = get_meta("description", false);
    }

    // Image: og:image
    preview.image = get_meta("og:image", true);

    // Site Name: og:site_name
    preview.site_name = get_meta("og:site_name", true);

    // Favicon: link[rel='shortcut icon'] -> link[rel='icon']
    if let Ok(selector) = scraper::Selector::parse("link[rel*='icon']") {
        if let Some(element) = document.select(&selector).next() {
            preview.favicon = element.value().attr("href").map(|s| s.to_string());
        }
    }

    preview
}
