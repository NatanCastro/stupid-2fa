use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const SECRET_KEY_ENV_NAME: &'static str = "STUPID_2FA_PRIVATE_KEY";

fn get_secret_key() -> String {
    env::var(SECRET_KEY_ENV_NAME).expect("Secret key is not defined")
}

pub fn generate_client_code() -> String {
    let device_id = Uuid::new_v4().to_string().replace("-", "");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}-{}", device_id, timestamp)
}

pub fn generate_unlock_code(lock_code: &str, subscription_days: i64) -> String {
    let secret_key = get_secret_key();
    let message = format!("{}-{}", lock_code, subscription_days);
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(result)
}

pub fn validate_unlock_code(lock_code: &str, unlock_code: &str, subscription_days: i64) -> bool {
    let secret_key = get_secret_key();
    let message = format!("{}-{}", lock_code, subscription_days);
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let expected_result = mac.finalize().into_bytes();
    let expected_unlock_code = URL_SAFE_NO_PAD.encode(expected_result);

    expected_unlock_code == unlock_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use std::env::set_var;
    use std::sync::Once;

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            set_var(SECRET_KEY_ENV_NAME, "VALUE");
        });
    }

    #[test]
    fn test_generate_lock_code() {
        initialize();
        let lock_code = generate_client_code();
        assert!(lock_code.contains('-'));
        let parts: Vec<&str> = lock_code.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(Uuid::parse_str(parts[0]).is_ok());
        assert!(parts[1].parse::<u64>().is_ok());
    }

    #[test]
    fn test_generate_unlock_code() {
        initialize();
        let lock_code = generate_client_code();
        let subscription_days = 30;
        let unlock_code = generate_unlock_code(&lock_code, subscription_days);
        assert!(!unlock_code.is_empty());
    }

    #[test]
    fn test_validate_unlock_code_valid() {
        initialize();
        let lock_code = generate_client_code();
        let subscription_days = 30;
        let unlock_code = generate_unlock_code(&lock_code, subscription_days);
        assert!(validate_unlock_code(
            &lock_code,
            &unlock_code,
            subscription_days,
        ));
    }

    #[test]
    fn test_validate_unlock_code_invalid() {
        initialize();
        let lock_code = generate_client_code();
        let invalid_unlock_code = "invalid_unlock_code";
        let subscription_days = 30;
        assert!(!validate_unlock_code(
            &lock_code,
            invalid_unlock_code,
            subscription_days,
        ));
    }

    #[test]
    fn test_validate_unlock_code_expired() {
        initialize();
        let device_id = Uuid::new_v4().to_string();
        let timestamp = (Utc::now() - Duration::days(31)).timestamp();
        let lock_code = format!("{}-{}", device_id, timestamp);
        let subscription_days = 30;
        let unlock_code = generate_unlock_code(&lock_code, subscription_days);
        assert!(validate_unlock_code(
            &lock_code,
            &unlock_code,
            subscription_days,
        ));
    }

    #[test]
    fn test_validate_unlock_code_not_expired() {
        initialize();
        let device_id = Uuid::new_v4().to_string();
        let timestamp = Utc::now().timestamp();
        let lock_code = format!("{}-{}", device_id, timestamp);
        let subscription_days = 30;
        let unlock_code = generate_unlock_code(&lock_code, subscription_days);
        assert!(validate_unlock_code(
            &lock_code,
            &unlock_code,
            subscription_days,
        ));
    }
}
