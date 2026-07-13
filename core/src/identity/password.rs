use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};

pub(crate) fn validate(password: &str) -> Result<(), &'static str> {
    if (6..=12).contains(&password.chars().count()) {
        Ok(())
    } else {
        Err("password must contain 6 to 12 characters")
    }
}

pub(crate) fn hash(password: &str) -> Result<String, String> {
    validate(password).map_err(str::to_owned)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map(|hash| hash.to_string())
        .map_err(|error| error.to_string())
}

pub(crate) fn verify(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded).ok().is_some_and(|hash| {
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_password_by_unicode_character_count() {
        assert!(validate("六个字符密码").is_ok());
        assert!(validate("短密码").is_err());
        assert!(validate("1234567890123").is_err());
    }

    #[test]
    fn hashes_and_verifies_password_without_storing_plaintext() {
        let encoded = hash("123456").unwrap();
        assert!(!encoded.contains("123456"));
        assert!(verify("123456", &encoded));
        assert!(!verify("654321", &encoded));
    }
}
