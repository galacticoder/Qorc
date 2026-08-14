const HARD_MAX_JSON_DEPTH: usize = 64;

pub fn enforce_bounded_json_structure(
    body: &[u8],
    max_depth: usize,
    max_structural_tokens: usize,
    max_string_bytes: usize,
) -> Result<(), String> {
    let mut stack = [0u8; HARD_MAX_JSON_DEPTH];
    let mut depth = 0usize;
    let mut structural_tokens = 0usize;
    let mut string_bytes = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'"' {
                in_string = false;
                continue;
            } else if byte == b'\\' {
                escaped = true;
            }
            string_bytes = string_bytes
                .checked_add(1)
                .ok_or_else(|| "invalid JSON".to_string())?;
            if string_bytes > max_string_bytes {
                return Err("JSON string exceeds the size limit".to_string());
            }
            continue;
        }

        match byte {
            b'"' => {
                in_string = true;
                string_bytes = 0;
            }
            b'{' | b'[' => {
                if depth >= max_depth || depth >= stack.len() {
                    return Err("JSON nesting exceeds the limit".to_string());
                }
                stack[depth] = byte;
                depth += 1;
                structural_tokens = structural_tokens.saturating_add(1);
            }
            b'}' | b']' => {
                let expected = if byte == b'}' { b'{' } else { b'[' };
                if depth == 0 || stack[depth - 1] != expected {
                    return Err("invalid JSON".to_string());
                }
                depth -= 1;
            }
            b',' | b':' => {
                structural_tokens = structural_tokens.saturating_add(1);
            }
            _ => {}
        }
        if structural_tokens > max_structural_tokens {
            return Err("JSON contains too many values".to_string());
        }
    }

    if in_string || escaped || depth != 0 {
        return Err("invalid JSON".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::enforce_bounded_json_structure;

    #[test]
    fn rejects_tree_string_and_depth_amplification() {
        assert!(
            enforce_bounded_json_structure(br#"{"ok":true,"items":["a","b"]}"#, 8, 16, 8).is_ok()
        );
        assert!(enforce_bounded_json_structure(br#"[[[[[]]]]]"#, 4, 16, 8).is_err());
        assert!(enforce_bounded_json_structure(br#"[1,2,3,4]"#, 8, 3, 8).is_err());
        assert!(enforce_bounded_json_structure(br#"{"value":"12345678"}"#, 8, 16, 8).is_ok());
        assert!(enforce_bounded_json_structure(br#"{"value":"123456789"}"#, 8, 16, 8).is_err());
        assert!(enforce_bounded_json_structure(br#"{"value":[1,2}"#, 8, 16, 8).is_err());
    }
}
