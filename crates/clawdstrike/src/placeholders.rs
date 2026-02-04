use crate::error::{Error, Result};

pub(crate) fn env_var_for_placeholder(raw: &str) -> std::result::Result<String, String> {
    if let Some(rest) = raw.strip_prefix("secrets.") {
        if rest.is_empty() {
            return Err("placeholder ${secrets.} is invalid".to_string());
        }
        return Ok(rest.to_string());
    }

    if raw.is_empty() {
        return Err("placeholder ${} is invalid".to_string());
    }

    Ok(raw.to_string())
}

pub(crate) fn resolve_placeholders_in_string(input: &str) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;

    while let Some(start_rel) = input[i..].find("${") {
        let start = i + start_rel;
        let after = start + 2;

        let Some(end_rel) = input[after..].find('}') else {
            break;
        };
        let end = after + end_rel;

        out.push_str(&input[i..start]);

        let raw = &input[after..end];
        let env_name = env_var_for_placeholder(raw)
            .map_err(|msg| Error::ConfigError(format!("invalid placeholder: {msg}")))?;
        let value = std::env::var(&env_name).map_err(|_| {
            Error::ConfigError(format!("missing environment variable {}", env_name))
        })?;
        out.push_str(&value);

        i = end + 1;
    }

    out.push_str(&input[i..]);
    Ok(out)
}

fn resolve_placeholders_in_json_inner(value: serde_json::Value) -> Result<serde_json::Value> {
    match value {
        serde_json::Value::String(s) => Ok(serde_json::Value::String(
            resolve_placeholders_in_string(&s)?,
        )),
        serde_json::Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(resolve_placeholders_in_json_inner(item)?);
            }
            Ok(serde_json::Value::Array(out))
        }
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k, resolve_placeholders_in_json_inner(v)?);
            }
            Ok(serde_json::Value::Object(out))
        }
        other => Ok(other),
    }
}

pub(crate) fn resolve_placeholders_in_json(value: serde_json::Value) -> Result<serde_json::Value> {
    resolve_placeholders_in_json_inner(value)
}
