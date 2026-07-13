use cookie::{Cookie, SameSite};

pub(crate) const NAME: &str = "crabouncer_session";

pub(crate) fn session(value: String, secure: bool, max_age_seconds: i64) -> String {
    Cookie::build((NAME, value))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::seconds(max_age_seconds))
        .build()
        .to_string()
}

pub(crate) fn expired(secure: bool) -> String {
    Cookie::build((NAME, ""))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(cookie::time::Duration::ZERO)
        .build()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_has_required_security_attributes() {
        let value = session("token".into(), true, 60);
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("Secure"));
        assert!(value.contains("SameSite=Lax"));
        assert!(value.contains("Path=/"));
    }
}
