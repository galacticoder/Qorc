pub(super) fn decode(value: &serde_json::Value, max_bytes: usize) -> Result<Vec<u8>, ()> {
    let values = value
        .as_array()
        .filter(|values| values.len() <= max_bytes)
        .ok_or(())?;
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or(())
        })
        .collect()
}
