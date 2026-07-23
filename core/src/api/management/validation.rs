use crate::error::{ApiError, Result};

pub(super) fn name(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ApiError::bad_request(format!("{field} must not be empty")))
    } else {
        Ok(())
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
