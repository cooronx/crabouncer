use crate::error::{ApiError, Result};

pub(super) fn name(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ApiError::bad_request(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

pub(super) fn immutable_key(value: &str) -> Result<String> {
    let key = value.trim().to_lowercase();
    let bytes = key.as_bytes();
    let valid = match bytes {
        [only] => only.is_ascii_lowercase(),
        [first, middle @ .., last] => {
            key.len() <= 64
                && first.is_ascii_lowercase()
                && middle
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
                && (last.is_ascii_lowercase() || last.is_ascii_digit())
        }
        [] => false,
    };
    if valid {
        Ok(key)
    } else {
        Err(ApiError::bad_request(
            "key must start with a lowercase letter, contain only lowercase letters, digits, or underscores, end with a letter or digit, and be at most 64 characters",
        ))
    }
}

pub(super) fn email(value: &str) -> Result<()> {
    let value = value.trim();
    if value.contains('@') && !value.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err(ApiError::bad_request("email is invalid"))
    }
}

pub(super) fn role(value: &str) -> Result<()> {
    if matches!(value, "owner" | "admin" | "member") {
        Ok(())
    } else {
        Err(ApiError::bad_request(
            "role must be owner, admin, or member",
        ))
    }
}

pub(super) fn redirects(values: &[String]) -> Result<()> {
    for value in values {
        let url = url::Url::parse(value)
            .map_err(|_| ApiError::bad_request("redirect URI must be absolute"))?;
        if url.fragment().is_some() {
            return Err(ApiError::bad_request(
                "redirect URI must not contain a fragment",
            ));
        }
    }
    Ok(())
}

pub(super) fn oidc_scopes(values: &[String]) -> Result<()> {
    if values.iter().all(|value| {
        matches!(
            value.as_str(),
            "openid" | "profile" | "email" | "offline_access"
        )
    }) {
        Ok(())
    } else {
        Err(ApiError::bad_request("unsupported OIDC scope"))
    }
}

pub(super) fn service_scopes(values: &[String]) -> Result<()> {
    if !values.is_empty()
        && values
            .iter()
            .all(|value| matches!(value.as_str(), "authzen:evaluate" | "resources:sync"))
    {
        Ok(())
    } else {
        Err(ApiError::bad_request("unsupported service account scope"))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn immutable_keys_are_trimmed_and_lowercased() {
        assert_eq!(super::immutable_key(" A ").unwrap(), "a");
        assert_eq!(
            super::immutable_key(" Quant_Research1 ").unwrap(),
            "quant_research1"
        );
    }

    #[test]
    fn immutable_keys_accept_the_supported_shape() {
        for key in [
            "a",
            "ab",
            "a0",
            "a_b",
            "a__b",
            &format!("a{}z", "_".repeat(62)),
        ] {
            assert!(super::immutable_key(key).is_ok(), "{key}");
        }
    }

    #[test]
    fn immutable_keys_reject_unsupported_shapes() {
        for key in [
            "",
            "_a",
            "1a",
            "a_",
            "a-b",
            "a b",
            "á",
            &format!("a{}z", "_".repeat(63)),
        ] {
            assert!(super::immutable_key(key).is_err(), "{key}");
        }
    }
}
