//! Canonical JSON for hashing/signatures (RFC 8785 JCS)
//!
//! Clawdstrike needs byte-for-byte identical canonical JSON across Rust/Python/TS.
//! We adopt RFC 8785 (JCS) and match ECMAScript `JSON.stringify()` number and
//! string escaping semantics.

use serde_json::Value;

use crate::error::{Error, Result};

/// Canonicalize a JSON value using RFC 8785 (JCS).
pub fn canonicalize(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

            let mut out = String::from("{");
            for (idx, (k, v)) in pairs.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(k));
                out.push_str("\":");
                out.push_str(&canonicalize(v)?);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(arr) => {
            let mut out = String::from("[");
            for (idx, v) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(v)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::String(s) => Ok(format!("\"{}\"", escape_json_string(s))),
        Value::Number(n) => canonicalize_number(n),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_string()),
    }
}

fn canonicalize_number(n: &serde_json::Number) -> Result<String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    if let Some(f) = n.as_f64() {
        return canonicalize_f64(f);
    }
    Err(Error::JsonError("Unsupported JSON number".into()))
}

/// JCS number serialization for IEEE-754 doubles (aligns with `JSON.stringify()`).
fn canonicalize_f64(v: f64) -> Result<String> {
    if !v.is_finite() {
        return Err(Error::JsonError(
            "Non-finite numbers are not valid JSON".into(),
        ));
    }
    if v == 0.0 {
        // Normalize -0 to 0
        return Ok("0".to_string());
    }

    let sign = if v.is_sign_negative() { "-" } else { "" };
    let abs = v.abs();
    let use_exponential = !(1e-6..1e21).contains(&abs);

    // Avoid `std` float formatting for canonicalization: it is not a stable cross-language
    // contract. Use a deterministic shortest-repr algorithm (ryu) and then apply JCS rules.
    let mut buf = ryu::Buffer::new();
    let rendered = buf.format_finite(abs);
    let (digits, sci_exp) = parse_to_scientific_parts(rendered)?;

    if !use_exponential {
        let rendered = render_decimal(&digits, sci_exp);
        return Ok(format!("{}{}", sign, rendered));
    }

    let mantissa = if digits.len() == 1 {
        digits.clone()
    } else {
        format!("{}.{}", &digits[0..1], &digits[1..])
    };
    let exp_sign = if sci_exp >= 0 { "+" } else { "" };
    Ok(format!("{sign}{mantissa}e{exp_sign}{sci_exp}"))
}

/// Parse a (debug-formatted) float string into (digits, scientific_exponent).
///
/// Output:
/// - `digits`: base-10 digits with no leading/trailing zeros (except "0")
/// - `scientific_exponent`: exponent for the form `d.ddd * 10^e`
fn parse_to_scientific_parts(s: &str) -> Result<(String, i32)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::JsonError("Empty number string".into()));
    }

    let (mantissa, exp_opt) = if let Some((m, e)) = s.split_once('e') {
        (m, Some(e))
    } else if let Some((m, e)) = s.split_once('E') {
        (m, Some(e))
    } else {
        (s, None)
    };

    let (digits_before_dot, mut digits) = if let Some((a, b)) = mantissa.split_once('.') {
        let frac = b.trim_end_matches('0');
        (a.len() as i32, format!("{a}{frac}"))
    } else {
        (mantissa.len() as i32, mantissa.to_string())
    };

    // Normalize digits.
    digits = digits.trim_start_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }
    digits = digits.trim_end_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }

    let sci_exp = if let Some(exp_str) = exp_opt {
        let exp: i32 = exp_str
            .parse()
            .map_err(|_| Error::JsonError(format!("Invalid exponent: {exp_str}")))?;
        exp + (digits_before_dot - 1)
    } else {
        // Decimal form: compute exponent from position of first significant digit.
        if mantissa.contains('.') {
            let (int_part, frac_part_raw) = mantissa
                .split_once('.')
                .ok_or_else(|| Error::JsonError("Invalid decimal".into()))?;
            let frac_part = frac_part_raw.trim_end_matches('0');

            let int_stripped = int_part.trim_start_matches('0');
            if !int_stripped.is_empty() {
                (int_stripped.len() as i32) - 1
            } else {
                let leading_zeros = frac_part.chars().take_while(|c| *c == '0').count() as i32;
                -(leading_zeros + 1)
            }
        } else {
            // Integer form (no dot)
            (mantissa.trim_start_matches('0').len() as i32) - 1
        }
    };

    Ok((digits, sci_exp))
}

fn render_decimal(digits: &str, sci_exp: i32) -> String {
    let digits_len = digits.len() as i32;
    let shift = sci_exp - (digits_len - 1);

    if shift >= 0 {
        let mut out = String::with_capacity(digits.len() + shift as usize);
        out.push_str(digits);
        out.extend(std::iter::repeat_n('0', shift as usize));
        return out;
    }

    let pos = digits_len + shift; // shift negative
    if pos > 0 {
        let pos_usize = pos as usize;
        let mut out = String::with_capacity(digits.len() + 1);
        out.push_str(&digits[..pos_usize]);
        out.push('.');
        out.push_str(&digits[pos_usize..]);
        trim_decimal(out)
    } else {
        let zeros = (-pos) as usize;
        let mut out = String::with_capacity(2 + zeros + digits.len());
        out.push_str("0.");
        out.extend(std::iter::repeat_n('0', zeros));
        out.push_str(digits);
        trim_decimal(out)
    }
}

fn trim_decimal(mut s: String) -> String {
    if let Some(dot) = s.find('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.len() == dot + 1 {
            // Trailing '.' left behind
            s.pop();
        }
    }
    s
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{0C}' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jcs_vector_b_numbers() {
        let value = serde_json::json!({
            "a": 1.0,
            "b": 0.0,
            "c": -0.0,
            "d": 1e21,
            "e": 1e20,
            "f": 1e-6,
            "g": 1e-7,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}"#
        );
    }

    #[test]
    fn jcs_vector_a_unicode_and_controls() {
        let value = serde_json::json!({
            "s": "e",
            "u2028": "\u{2028}",
            "u2029": "\u{2029}",
            "emoji": "X",
            "nl": "\n",
            "tab": "\t",
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            format!(
                r#"{{"emoji":"X","nl":"\n","s":"e","tab":"\t","u2028":"{}","u2029":"{}"}}"#,
                "\u{2028}", "\u{2029}"
            )
        );
    }

    #[test]
    fn jcs_vector_c_escape_shortcuts() {
        let value = serde_json::json!({
            "b": "\u{0008}",
            "f": "\u{000c}",
            "ctl": "\u{000f}",
            "quote": "\"",
            "backslash": "\\",
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"b":"\b","backslash":"\\","ctl":"\u000f","f":"\f","quote":"\""}"#
        );
    }

    #[test]
    fn jcs_vector_d_numeric_string_keys() {
        let value = serde_json::json!({
            "2": "b",
            "10": "a",
            "a": 0,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"10":"a","2":"b","a":0}"#);
    }

    #[test]
    fn sorted_keys() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn nested_objects() {
        let value = serde_json::json!({
            "outer": {
                "inner": "value"
            }
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"outer":{"inner":"value"}}"#);
    }

    #[test]
    fn arrays() {
        let value = serde_json::json!([1, 2, 3]);
        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, "[1,2,3]");
    }
}
