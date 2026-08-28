//! Native-only private message content handling

use serde::Serialize;
use std::collections::HashSet;
use std::io::Cursor;
use std::sync::LazyLock;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::database::DatabaseManager;
use crate::error::{QorError, QorResult};
use crate::signal_protocol::PendingDecryptedMessage;

const MAX_PRIVATE_MESSAGE_CHARS: usize = 16 * 1024;
const MAX_RENDER_WIDTH: u32 = 800;
const MAX_RENDER_HEIGHT: u32 = 4096;
const MAX_USERNAME_BYTES: usize = 100;
const MAX_LINK_URL_BYTES: usize = 2048;
const MAX_MESSAGE_LINK_PREVIEWS: usize = 3;

static MESSAGE_LINK_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)(?:https?://|www\.)[^\s<>{}\[\]"']+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::[0-9]{1,5})?(?:[/?#][^\s<>{}\[\]"']*)?"#,
    )
    .expect("valid message link regex")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundContentBinding {
    pub recipient: String,
    pub application_type: String,
    pub wire_message_id: String,
}

#[derive(Debug)]
pub struct NativeMessageContentRecord {
    pub content: Zeroizing<Vec<u8>>,
    pub outbound: Option<OutboundContentBinding>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentCommitResult {
    pub stored: bool,
    pub duplicate: bool,
}

#[derive(Debug)]
pub struct RedactedApplicationPlaintext {
    pub plaintext: String,
    pub content_ref: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RenderedMessageContent {
    pub png_base64: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeMessageLinkTarget {
    pub url: String,
    pub display_url: String,
    pub host: String,
}

fn trim_link_candidate(value: &str) -> &str {
    value
        .trim_start_matches(['(', '[', '{', '<', '"', '\''])
        .trim_end_matches(['.', ',', '!', ';', ':', ')', ']', '}', '>', '"', '\''])
}

fn looks_like_bare_domain(value: &str) -> bool {
    let authority = value.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        Some(_) => return false,
        None => authority,
    };
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || label.starts_with('-')
                || label.ends_with('-')
        })
    {
        return false;
    }
    labels.last().is_some_and(|label| {
        (2..=24).contains(&label.len()) && label.bytes().all(|byte| byte.is_ascii_alphabetic())
    })
}

pub fn parse_message_link(value: &str) -> Option<NativeMessageLinkTarget> {
    let candidate = trim_link_candidate(value);
    if candidate.is_empty() || candidate.len() > MAX_LINK_URL_BYTES {
        return None;
    }
    let normalized = if candidate
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("www."))
        || looks_like_bare_domain(candidate)
    {
        format!("https://{candidate}")
    } else {
        candidate.to_string()
    };
    let parsed = url::Url::parse(&normalized).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?.trim_end_matches('.').to_string();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let url = parsed.to_string();
    if url.len() > MAX_LINK_URL_BYTES {
        return None;
    }
    let display_url = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url)
        .trim_end_matches('/')
        .to_string();
    Some(NativeMessageLinkTarget {
        url,
        display_url,
        host,
    })
}

pub fn message_links(content: &str) -> Vec<NativeMessageLinkTarget> {
    let mut seen = HashSet::with_capacity(MAX_MESSAGE_LINK_PREVIEWS);
    MESSAGE_LINK_RE
        .find_iter(content)
        .filter(|matched| {
            matched.start() == 0
                || content[..matched.start()]
                    .chars()
                    .next_back()
                    .is_none_or(|character| character != '@')
        })
        .filter_map(|matched| parse_message_link(matched.as_str()))
        .filter(|target| seen.insert(target.url.clone()))
        .take(MAX_MESSAGE_LINK_PREVIEWS)
        .collect()
}

fn parse_rgb(color: &str) -> QorResult<(u8, u8, u8)> {
    if color.len() != 7 || !color.starts_with('#') || !color[1..].is_ascii() {
        return Err(QorError::InvalidArgument(
            "Invalid native message render color".to_string(),
        ));
    }
    let red = u8::from_str_radix(&color[1..3], 16).map_err(|_| {
        QorError::InvalidArgument("Invalid native message render color".to_string())
    })?;
    let green = u8::from_str_radix(&color[3..5], 16).map_err(|_| {
        QorError::InvalidArgument("Invalid native message render color".to_string())
    })?;
    let blue = u8::from_str_radix(&color[5..7], 16).map_err(|_| {
        QorError::InvalidArgument("Invalid native message render color".to_string())
    })?;
    Ok((red, green, blue))
}

fn blend_pixel(destination: &mut [u8], source: [u8; 4]) {
    let source_alpha = u16::from(source[3]);
    let inverse = 255u16.saturating_sub(source_alpha);
    let destination_alpha = u16::from(destination[3]);
    let output_alpha = source_alpha + (destination_alpha * inverse + 127) / 255;
    if output_alpha == 0 {
        destination.fill(0);
        return;
    }
    for channel in 0..3 {
        let source_component = u16::from(source[channel]) * source_alpha;
        let destination_component =
            u16::from(destination[channel]) * destination_alpha * inverse / 255;
        destination[channel] = ((source_component + destination_component) / output_alpha) as u8;
    }
    destination[3] = output_alpha.min(255) as u8;
}

pub fn render_private_message(
    content: &str,
    max_width: u32,
    font_size: f32,
    color: &str,
    single_line: bool,
    max_lines: u32,
) -> QorResult<RenderedMessageContent> {
    use base64::Engine as _;
    use cosmic_text::{Attrs, Buffer, Color, FontSystem, Metrics, Shaping, SwashCache, Wrap};
    use image::{ExtendedColorType, ImageEncoder, codecs::png::PngEncoder};

    if !(20..=MAX_RENDER_WIDTH).contains(&max_width)
        || !font_size.is_finite()
        || !(10.0..=32.0).contains(&font_size)
        || max_lines > 8
    {
        return Err(QorError::InvalidArgument(
            "Invalid native message render dimensions".to_string(),
        ));
    }
    let (red, green, blue) = parse_rgb(color)?;
    let line_height = (font_size * 1.4).ceil();
    let mut font_system = FontSystem::new();
    let mut swash_cache = SwashCache::new();
    let measure_single_line = |value: &str, font_system: &mut FontSystem| {
        let mut measurement = Buffer::new(font_system, Metrics::new(font_size, line_height));
        {
            let mut borrowed = measurement.borrow_with(font_system);
            borrowed.set_wrap(Wrap::None);
            borrowed.set_size(None, None);
            borrowed.set_text(value, &Attrs::new(), Shaping::Advanced);
            borrowed.shape_until_scroll(false);
        }
        measurement
            .layout_runs()
            .map(|run| run.line_w)
            .fold(0.0f32, f32::max)
    };
    let render_text = if single_line {
        let normalized = Zeroizing::new(content.split_whitespace().collect::<Vec<_>>().join(" "));
        let available_width = (max_width - 4) as f32;
        if measure_single_line(normalized.as_str(), &mut font_system) <= available_width {
            normalized
        } else {
            let mut boundaries = normalized
                .char_indices()
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            boundaries.push(normalized.len());
            let mut low = 0usize;
            let mut high = boundaries.len();
            while low + 1 < high {
                let middle = low + (high - low) / 2;
                let prefix = normalized[..boundaries[middle]].trim_end();
                let candidate = Zeroizing::new(format!("{prefix}..."));
                if measure_single_line(candidate.as_str(), &mut font_system) <= available_width {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            let prefix = normalized[..boundaries[low]].trim_end();
            Zeroizing::new(format!("{prefix}..."))
        }
    } else if max_lines > 0 {
        let available_width = (max_width - 4) as f32;
        let line_limit = max_lines as usize;
        let fits = |value: &str, font_system: &mut FontSystem| {
            let mut measurement = Buffer::new(font_system, Metrics::new(font_size, line_height));
            {
                let mut borrowed = measurement.borrow_with(font_system);
                borrowed.set_wrap(Wrap::WordOrGlyph);
                borrowed.set_size(Some(available_width), None);
                borrowed.set_text(value, &Attrs::new(), Shaping::Advanced);
                borrowed.shape_until_scroll(false);
            }
            measurement.layout_runs().take(line_limit + 1).count() <= line_limit
        };
        if fits(content, &mut font_system) {
            Zeroizing::new(content.to_owned())
        } else {
            let mut boundaries = content
                .char_indices()
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            boundaries.push(content.len());
            let mut low = 0usize;
            let mut high = boundaries.len();
            while low + 1 < high {
                let middle = low + (high - low) / 2;
                let prefix = content[..boundaries[middle]].trim_end();
                let candidate = Zeroizing::new(format!("{prefix}..."));
                if fits(candidate.as_str(), &mut font_system) {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            let prefix = content[..boundaries[low]].trim_end();
            Zeroizing::new(format!("{prefix}..."))
        }
    } else {
        Zeroizing::new(content.to_owned())
    };
    let mut buffer = Buffer::new(&mut font_system, Metrics::new(font_size, line_height));
    {
        let mut borrowed = buffer.borrow_with(&mut font_system);
        borrowed.set_wrap(if single_line {
            Wrap::None
        } else {
            Wrap::WordOrGlyph
        });
        borrowed.set_size(Some((max_width - 4) as f32), None);
        borrowed.set_text(render_text.as_str(), &Attrs::new(), Shaping::Advanced);
        borrowed.shape_until_scroll(false);
    }
    let mut measured_width = 20.0f32;
    let mut measured_height = line_height;
    for run in buffer.layout_runs() {
        measured_width = measured_width.max(run.line_w + 4.0);
        measured_height = measured_height.max(run.line_top + run.line_height + 4.0);
    }
    let width = measured_width.ceil().clamp(20.0, max_width as f32) as u32;
    let height = measured_height
        .ceil()
        .clamp(line_height, MAX_RENDER_HEIGHT as f32) as u32;
    let pixel_len = usize::try_from(width)
        .ok()
        .and_then(|value| value.checked_mul(height as usize))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| QorError::InvalidArgument("Native render size overflow".to_string()))?;
    let mut pixels = Zeroizing::new(vec![0u8; pixel_len]);
    let base_color = Color::rgb(red, green, blue);
    buffer.draw(
        &mut font_system,
        &mut swash_cache,
        base_color,
        |x, y, glyph_width, glyph_height, glyph_color| {
            for offset_y in 0..glyph_height {
                for offset_x in 0..glyph_width {
                    let target_x = x + offset_x as i32 + 2;
                    let target_y = y + offset_y as i32 + 2;
                    if target_x < 0
                        || target_y < 0
                        || target_x >= width as i32
                        || target_y >= height as i32
                    {
                        continue;
                    }
                    let index = ((target_y as usize * width as usize) + target_x as usize) * 4;
                    blend_pixel(&mut pixels[index..index + 4], glyph_color.as_rgba());
                }
            }
        },
    );
    let mut encoded = Zeroizing::new(Vec::new());
    PngEncoder::new(&mut Cursor::new(&mut *encoded))
        .write_image(pixels.as_slice(), width, height, ExtendedColorType::Rgba8)
        .map_err(|_| QorError::Internal("Native message PNG encoding failed".to_string()))?;
    if encoded.len() > 4 * 1024 * 1024 {
        return Err(QorError::InvalidArgument(
            "Native message render output exceeded its limit".to_string(),
        ));
    }
    Ok(RenderedMessageContent {
        png_base64: base64::engine::general_purpose::STANDARD.encode(encoded.as_slice()),
        width,
        height,
    })
}

fn private_text_application_type(application_type: &str) -> bool {
    matches!(application_type, "message" | "edit-message")
}

fn valid_username(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= MAX_USERNAME_BYTES
        && value == value.trim().to_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn encode_record(record: &NativeMessageContentRecord) -> QorResult<Zeroizing<Vec<u8>>> {
    let (recipient, application_type, wire_message_id) = match record.outbound.as_ref() {
        Some(binding) => (
            binding.recipient.as_bytes(),
            binding.application_type.as_bytes(),
            binding.wire_message_id.as_bytes(),
        ),
        None => (&[][..], &[][..], &[][..]),
    };
    let recipient_len = u16::try_from(recipient.len())
        .map_err(|_| QorError::InvalidArgument("Invalid native content binding".to_string()))?;
    let type_len = u16::try_from(application_type.len())
        .map_err(|_| QorError::InvalidArgument("Invalid native content binding".to_string()))?;
    let wire_len = u16::try_from(wire_message_id.len())
        .map_err(|_| QorError::InvalidArgument("Invalid native content binding".to_string()))?;
    let content_len = u32::try_from(record.content.len())
        .map_err(|_| QorError::InvalidArgument("Invalid native message content".to_string()))?;
    let capacity = 4usize
        .checked_add(1)
        .and_then(|value| value.checked_add(2 + 2 + 2 + 4))
        .and_then(|value| value.checked_add(recipient.len()))
        .and_then(|value| value.checked_add(application_type.len()))
        .and_then(|value| value.checked_add(wire_message_id.len()))
        .and_then(|value| value.checked_add(record.content.len()))
        .ok_or_else(|| {
            QorError::InvalidArgument("Native content record is too large".to_string())
        })?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
    encoded.extend_from_slice(crate::protocol_keys::NATIVE_MESSAGE_CONTENT_MAGIC);
    encoded.push(u8::from(record.outbound.is_some()));
    encoded.extend_from_slice(&recipient_len.to_be_bytes());
    encoded.extend_from_slice(&type_len.to_be_bytes());
    encoded.extend_from_slice(&wire_len.to_be_bytes());
    encoded.extend_from_slice(&content_len.to_be_bytes());
    encoded.extend_from_slice(recipient);
    encoded.extend_from_slice(application_type);
    encoded.extend_from_slice(wire_message_id);
    encoded.extend_from_slice(record.content.as_slice());
    Ok(encoded)
}

fn read_u16(input: &[u8], offset: &mut usize) -> QorResult<usize> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| QorError::DecryptionFailed("Invalid native content record".to_string()))?;
    let bytes: [u8; 2] = input
        .get(*offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| QorError::DecryptionFailed("Invalid native content record".to_string()))?;
    *offset = end;
    Ok(u16::from_be_bytes(bytes) as usize)
}

fn decode_record(encoded: Zeroizing<Vec<u8>>) -> QorResult<NativeMessageContentRecord> {
    if encoded.len() < 15
        || encoded.get(..4) != Some(crate::protocol_keys::NATIVE_MESSAGE_CONTENT_MAGIC.as_slice())
    {
        return Err(QorError::DecryptionFailed(
            "Invalid native content record".to_string(),
        ));
    }
    let has_outbound = match encoded[4] {
        0 => false,
        1 => true,
        _ => {
            return Err(QorError::DecryptionFailed(
                "Invalid native content record".to_string(),
            ));
        }
    };
    let mut offset = 5usize;
    let recipient_len = read_u16(encoded.as_slice(), &mut offset)?;
    let type_len = read_u16(encoded.as_slice(), &mut offset)?;
    let wire_len = read_u16(encoded.as_slice(), &mut offset)?;
    let content_len_end = offset
        .checked_add(4)
        .ok_or_else(|| QorError::DecryptionFailed("Invalid native content record".to_string()))?;
    let content_len_bytes: [u8; 4] = encoded
        .get(offset..content_len_end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| QorError::DecryptionFailed("Invalid native content record".to_string()))?;
    offset = content_len_end;
    let content_len = u32::from_be_bytes(content_len_bytes) as usize;
    let total = offset
        .checked_add(recipient_len)
        .and_then(|value| value.checked_add(type_len))
        .and_then(|value| value.checked_add(wire_len))
        .and_then(|value| value.checked_add(content_len))
        .ok_or_else(|| QorError::DecryptionFailed("Invalid native content record".to_string()))?;
    if total != encoded.len() || content_len == 0 || content_len > 64 * 1024 {
        return Err(QorError::DecryptionFailed(
            "Invalid native content record".to_string(),
        ));
    }
    let take_string = |start: usize, len: usize| -> QorResult<String> {
        String::from_utf8(encoded[start..start + len].to_vec())
            .map_err(|_| QorError::DecryptionFailed("Invalid native content record".to_string()))
    };
    let recipient = take_string(offset, recipient_len)?;
    offset += recipient_len;
    let application_type = take_string(offset, type_len)?;
    offset += type_len;
    let wire_message_id = take_string(offset, wire_len)?;
    offset += wire_len;
    let content = Zeroizing::new(encoded[offset..].to_vec());
    let outbound = if has_outbound {
        if !valid_username(&recipient)
            || !private_text_application_type(&application_type)
            || !valid_message_id(&wire_message_id)
        {
            return Err(QorError::DecryptionFailed(
                "Invalid native content binding".to_string(),
            ));
        }
        Some(OutboundContentBinding {
            recipient,
            application_type,
            wire_message_id,
        })
    } else {
        if recipient_len != 0 || type_len != 0 || wire_len != 0 {
            return Err(QorError::DecryptionFailed(
                "Invalid native content record".to_string(),
            ));
        }
        None
    };
    Ok(NativeMessageContentRecord { content, outbound })
}

pub fn load_native_content_record(
    db: &DatabaseManager,
    storage_id: &str,
) -> QorResult<Option<NativeMessageContentRecord>> {
    db.get_native_message_content(storage_id)?
        .map(decode_record)
        .transpose()
}

fn persist_native_content_record(
    db: &DatabaseManager,
    storage_id: &str,
    record: &NativeMessageContentRecord,
) -> QorResult<()> {
    let encoded = encode_record(record)?;
    db.set_native_message_content(storage_id, encoded.as_slice())
}

fn valid_message_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b':' | b'+' | b'/' | b'=' | b'-')
        })
}

fn sanitize_private_text(value: &str) -> QorResult<Zeroizing<String>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(QorError::InvalidArgument(
            "Private message content is empty".to_string(),
        ));
    }
    let mut sanitized = Zeroizing::new(String::with_capacity(trimmed.len().min(64 * 1024)));
    for character in trimmed.chars().take(MAX_PRIVATE_MESSAGE_CHARS) {
        if matches!(character, '\u{0000}'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}' | '\u{007F}')
        {
            continue;
        }
        sanitized.push(character);
    }
    if sanitized.is_empty() || sanitized.len() > 64 * 1024 {
        return Err(QorError::InvalidArgument(
            "Private message content is invalid".to_string(),
        ));
    }
    Ok(sanitized)
}

fn payload_content(
    pending: &PendingDecryptedMessage,
    expected_wire_message_id: &str,
) -> QorResult<Zeroizing<String>> {
    if !private_text_application_type(&pending.application_type)
        || !valid_message_id(expected_wire_message_id)
    {
        return Err(QorError::InvalidArgument(
            "Invalid private message content request".to_string(),
        ));
    }
    let mut payload: serde_json::Value = serde_json::from_str(&pending.plaintext)
        .map_err(|_| QorError::InvalidArgument("Invalid private message payload".to_string()))?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| QorError::InvalidArgument("Invalid private message payload".to_string()))?;
    if object.get("type").and_then(serde_json::Value::as_str)
        != Some(pending.application_type.as_str())
    {
        return Err(QorError::InvalidArgument(
            "Private message type binding mismatch".to_string(),
        ));
    }
    let selector = if pending.application_type == "edit-message" {
        "editMessageId"
    } else {
        "messageId"
    };
    if object.get(selector).and_then(serde_json::Value::as_str) != Some(expected_wire_message_id) {
        return Err(QorError::InvalidArgument(
            "Private message identifier binding mismatch".to_string(),
        ));
    }
    let content = object
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            QorError::InvalidArgument("Private message content is missing".to_string())
        })?;
    sanitize_private_text(content)
}

pub fn redact_application_plaintext(
    plaintext: &str,
    application_type: &str,
    pending_id: &str,
) -> QorResult<RedactedApplicationPlaintext> {
    if !private_text_application_type(application_type) {
        return Ok(RedactedApplicationPlaintext {
            plaintext: plaintext.to_string(),
            content_ref: None,
        });
    }
    if !valid_message_id(pending_id) {
        return Err(QorError::InvalidArgument(
            "Invalid staged message content reference".to_string(),
        ));
    }
    let mut payload: serde_json::Value = serde_json::from_str(plaintext)
        .map_err(|_| QorError::InvalidArgument("Invalid private message payload".to_string()))?;
    let object = payload
        .as_object_mut()
        .ok_or_else(|| QorError::InvalidArgument("Invalid private message payload".to_string()))?;
    if object.get("type").and_then(serde_json::Value::as_str) != Some(application_type) {
        return Err(QorError::InvalidArgument(
            "Private message type binding mismatch".to_string(),
        ));
    }
    let content = object
        .get("content")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            QorError::InvalidArgument("Private message content is missing".to_string())
        })?;
    let sanitized = sanitize_private_text(content)?;
    if let Some(serde_json::Value::String(mut sensitive)) = object.insert(
        "content".to_string(),
        serde_json::Value::String(String::new()),
    ) {
        use zeroize::Zeroize;
        sensitive.zeroize();
    }
    object.insert(
        "nativeContentRef".to_string(),
        serde_json::Value::String(pending_id.to_string()),
    );
    let serialized = serde_json::to_string(&payload)
        .map_err(|_| QorError::InvalidArgument("Invalid private message payload".to_string()))?;
    drop(sanitized);
    Ok(RedactedApplicationPlaintext {
        plaintext: serialized,
        content_ref: Some(pending_id.to_string()),
    })
}

pub fn commit_pending_content(
    db: &DatabaseManager,
    pending: &PendingDecryptedMessage,
    expected_wire_message_id: &str,
    storage_id: &str,
    overwrite: bool,
) -> QorResult<ContentCommitResult> {
    if !valid_message_id(storage_id) {
        return Err(QorError::InvalidArgument(
            "Invalid private message storage identifier".to_string(),
        ));
    }
    let content = payload_content(pending, expected_wire_message_id)?;
    if let Some(existing) = load_native_content_record(db, storage_id)? {
        let duplicate = existing.content.len() == content.len()
            && bool::from(existing.content.as_slice().ct_eq(content.as_bytes()));
        if duplicate {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: true,
            });
        }
        if !overwrite {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: false,
            });
        }
    }
    persist_native_content_record(
        db,
        storage_id,
        &NativeMessageContentRecord {
            content: Zeroizing::new(content.as_bytes().to_vec()),
            outbound: None,
        },
    )?;
    Ok(ContentCommitResult {
        stored: true,
        duplicate: false,
    })
}

pub fn store_outgoing_content(
    db: &DatabaseManager,
    storage_id: &str,
    content: &str,
    recipient: &str,
    application_type: &str,
    wire_message_id: &str,
    overwrite: bool,
) -> QorResult<ContentCommitResult> {
    if !valid_message_id(storage_id)
        || !valid_username(recipient)
        || !private_text_application_type(application_type)
        || !valid_message_id(wire_message_id)
        || storage_id != wire_message_id
    {
        return Err(QorError::InvalidArgument(
            "Invalid private message storage identifier".to_string(),
        ));
    }
    let content = sanitize_private_text(content)?;
    let outbound = OutboundContentBinding {
        recipient: recipient.to_string(),
        application_type: application_type.to_string(),
        wire_message_id: wire_message_id.to_string(),
    };
    if let Some(existing) = load_native_content_record(db, storage_id)? {
        let duplicate = existing.content.len() == content.len()
            && bool::from(existing.content.as_slice().ct_eq(content.as_bytes()))
            && existing.outbound.as_ref() == Some(&outbound);
        if duplicate {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: true,
            });
        }
        if !overwrite {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: false,
            });
        }
    }
    persist_native_content_record(
        db,
        storage_id,
        &NativeMessageContentRecord {
            content: Zeroizing::new(content.as_bytes().to_vec()),
            outbound: Some(outbound),
        },
    )?;
    Ok(ContentCommitResult {
        stored: true,
        duplicate: false,
    })
}

pub fn clone_content_for_display(
    db: &DatabaseManager,
    source_id: &str,
    target_id: &str,
    overwrite: bool,
) -> QorResult<ContentCommitResult> {
    if !valid_message_id(source_id) || !valid_message_id(target_id) {
        return Err(QorError::InvalidArgument(
            "Invalid private message storage identifier".to_string(),
        ));
    }
    let source = load_native_content_record(db, source_id)?.ok_or_else(|| {
        QorError::NotInitialized("Native message content is unavailable".to_string())
    })?;
    if let Some(existing) = load_native_content_record(db, target_id)? {
        let duplicate = existing.content.len() == source.content.len()
            && bool::from(existing.content.as_slice().ct_eq(source.content.as_slice()));
        if duplicate {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: true,
            });
        }
        if !overwrite {
            return Ok(ContentCommitResult {
                stored: false,
                duplicate: false,
            });
        }
    }
    persist_native_content_record(
        db,
        target_id,
        &NativeMessageContentRecord {
            content: Zeroizing::new(source.content.as_slice().to_vec()),
            outbound: None,
        },
    )?;
    Ok(ContentCommitResult {
        stored: true,
        duplicate: false,
    })
}

pub fn revoke_outbound_binding(db: &DatabaseManager, storage_id: &str) -> QorResult<bool> {
    let Some(mut record) = load_native_content_record(db, storage_id)? else {
        return Ok(false);
    };
    if record.outbound.take().is_none() {
        return Ok(true);
    }
    persist_native_content_record(db, storage_id, &record)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_signal_plaintext_is_redacted_before_ipc() {
        let pending_id = "A".repeat(44);
        let plaintext =
            r#"{"type":"message","messageId":"wire-1","content":" secret text ","from":"alice"}"#;
        let redacted = redact_application_plaintext(plaintext, "message", &pending_id)
            .expect("private payload redacts");
        assert_eq!(redacted.content_ref.as_deref(), Some(pending_id.as_str()));
        assert!(!redacted.plaintext.contains("secret text"));
        assert!(redacted.plaintext.contains("nativeContentRef"));
        assert!(redacted.plaintext.contains(r#""content":"""#));
    }

    #[test]
    fn non_message_signal_plaintext_is_unchanged() {
        let plaintext = r#"{"type":"typing-start","from":"alice"}"#;
        let redacted = redact_application_plaintext(plaintext, "typing-start", "unused")
            .expect("non-message payload passes through");
        assert_eq!(redacted.plaintext, plaintext);
        assert!(redacted.content_ref.is_none());
    }

    #[test]
    fn native_record_round_trip_preserves_exact_send_binding() {
        let original = NativeMessageContentRecord {
            content: Zeroizing::new(b"private text".to_vec()),
            outbound: Some(OutboundContentBinding {
                recipient: "bob.smith-2".to_string(),
                application_type: "message".to_string(),
                wire_message_id: "wire-1".to_string(),
            }),
        };
        let decoded = decode_record(encode_record(&original).expect("record encodes"))
            .expect("record decodes");
        assert_eq!(decoded.content.as_slice(), b"private text");
        assert_eq!(decoded.outbound, original.outbound);
    }

    #[test]
    fn malformed_native_record_fails_closed() {
        assert!(decode_record(Zeroizing::new(b"private text".to_vec())).is_err());
        let mut encoded = encode_record(&NativeMessageContentRecord {
            content: Zeroizing::new(b"private text".to_vec()),
            outbound: None,
        })
        .expect("record encodes");
        encoded[4] = 2;
        assert!(decode_record(encoded).is_err());
    }

    #[test]
    fn native_renderer_emits_pixels_without_plaintext_metadata() {
        use base64::Engine as _;
        let rendered = render_private_message(
            "unique-secret-render-sentinel",
            320,
            14.0,
            "#ffffff",
            false,
            0,
        )
        .expect("message renders");
        let png = base64::engine::general_purpose::STANDARD
            .decode(rendered.png_base64)
            .expect("PNG is base64");
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert!(
            !png.windows(b"unique-secret-render-sentinel".len())
                .any(|window| { window == b"unique-secret-render-sentinel" })
        );
    }

    #[test]
    fn extracts_normalizes_and_limits_message_links() {
        let links = message_links(
            "See [repo](https://example.com/a?b=1), www.test.org, third.test/path, https://fourth.test and https://example.com/a?b=1.",
        );
        assert_eq!(links.len(), 3);
        assert_eq!(links[0].url, "https://example.com/a?b=1");
        assert_eq!(links[0].display_url, "example.com/a?b=1");
        assert_eq!(links[0].host, "example.com");
        assert_eq!(links[1].url, "https://www.test.org/");
        assert_eq!(links[2].url, "https://third.test/path");
    }

    #[test]
    fn ignores_unsafe_message_links() {
        assert!(message_links("javascript:alert(1)").is_empty());
        assert!(message_links("https://user:pass@example.com/").is_empty());
        assert!(message_links("person@example.com").is_empty());
    }
}
