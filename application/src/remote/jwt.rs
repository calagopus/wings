use compact_str::ToCompactString;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashMap, sync::Arc};

#[derive(Debug, Clone, Copy)]
pub enum JwtValidateError {
    Expired,
    NotYetValid,
    InvalidIssuedAt,
    Denied,
}

impl std::fmt::Display for JwtValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Expired => write!(f, "token is expired"),
            Self::NotYetValid => write!(f, "token is not yet valid"),
            Self::InvalidIssuedAt => write!(f, "token has invalid issued at time"),
            Self::Denied => write!(f, "token has been denied"),
        }
    }
}

impl std::error::Error for JwtValidateError {}

#[derive(Deserialize, Serialize)]
pub struct BasePayload {
    #[serde(default)]
    pub scope: compact_str::CompactString,

    #[serde(rename = "iss")]
    pub issuer: compact_str::CompactString,
    #[serde(rename = "sub")]
    pub subject: Option<compact_str::CompactString>,
    #[serde(rename = "aud")]
    pub audience: Vec<compact_str::CompactString>,
    #[serde(rename = "exp")]
    pub expiration_time: Option<i64>,
    #[serde(rename = "nbf")]
    pub not_before: Option<i64>,
    #[serde(rename = "iat")]
    pub issued_at: Option<i64>,
    #[serde(rename = "jti")]
    pub jwt_id: compact_str::CompactString,
}

impl BasePayload {
    pub fn validate(
        &self,
        client: &JwtClient,
        scope: Option<&str>,
    ) -> Result<(), JwtValidateError> {
        let now = chrono::Utc::now().timestamp();

        if let Some(exp) = self.expiration_time {
            if exp < now {
                return Err(JwtValidateError::Expired);
            }
        } else {
            return Err(JwtValidateError::Expired);
        }

        if let Some(nbf) = self.not_before
            && nbf > now
        {
            return Err(JwtValidateError::NotYetValid);
        }

        if let Some(iat) = self.issued_at {
            if iat - 5 > now || iat < client.boot_time.timestamp() {
                return Err(JwtValidateError::InvalidIssuedAt);
            }
        } else {
            return Err(JwtValidateError::InvalidIssuedAt);
        }

        if let Some(expired_until) = client.denied_jtokens.read().get(&self.jwt_id)
            && let Some(issued) = self.issued_at
            && issued <= expired_until.timestamp()
        {
            return Err(JwtValidateError::Denied);
        }

        if let Some(scope) = scope
            && self.scope.split(',').all(|s| s.trim() != scope)
        {
            return Err(JwtValidateError::Denied);
        }

        Ok(())
    }
}

type CountingMap = HashMap<
    compact_str::CompactString,
    (
        std::sync::atomic::AtomicUsize,
        chrono::DateTime<chrono::Utc>,
    ),
>;

pub struct JwtClient {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
    pub boot_time: chrono::DateTime<chrono::Utc>,
    pub max_jwt_uses: usize,

    pub denied_jtokens:
        Arc<RwLock<HashMap<compact_str::CompactString, chrono::DateTime<chrono::Utc>>>>,
    pub seen_jtoken_ids: Arc<RwLock<CountingMap>>,
}

impl JwtClient {
    pub fn new(config: &crate::config::InnerConfig) -> Self {
        let denied_jtokens = Arc::new(RwLock::new(HashMap::new()));
        let seen_jtoken_ids = Arc::new(RwLock::new(HashMap::new()));

        tokio::spawn({
            let denied_jtokens = Arc::clone(&denied_jtokens);
            let seen_jtoken_ids = Arc::clone(&seen_jtoken_ids);

            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                    let mut denied = denied_jtokens.write();
                    denied.retain(|_, &mut expiration| {
                        expiration > chrono::Utc::now() - chrono::Duration::hours(1)
                    });
                    drop(denied);

                    let mut seen = seen_jtoken_ids.write();
                    seen.retain(|_, (_, expiration)| {
                        *expiration > chrono::Utc::now() - chrono::Duration::hours(1)
                    });
                    drop(seen);
                }
            }
        });

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        Self {
            decoding_key: DecodingKey::from_secret(config.token.as_bytes()),
            validation,
            boot_time: chrono::Utc::now(),
            max_jwt_uses: config.api.max_jwt_uses,

            denied_jtokens,
            seen_jtoken_ids,
        }
    }

    #[inline]
    pub fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
    ) -> Result<T, jsonwebtoken::errors::Error> {
        let data = jsonwebtoken::decode::<T>(token, &self.decoding_key, &self.validation)?;
        Ok(data.claims)
    }

    pub fn limited_jwt_id(&self, id: &str) -> bool {
        if self.max_jwt_uses == 0 {
            return true;
        }

        let claim_use = |count: &std::sync::atomic::AtomicUsize| {
            count
                .try_update(
                    std::sync::atomic::Ordering::SeqCst,
                    std::sync::atomic::Ordering::SeqCst,
                    |count| (count < self.max_jwt_uses).then_some(count + 1),
                )
                .is_ok()
        };

        let seen = self.seen_jtoken_ids.read();
        if let Some((count, _)) = seen.get(id) {
            return claim_use(count);
        }
        drop(seen);

        match self.seen_jtoken_ids.write().entry(id.to_compact_string()) {
            std::collections::hash_map::Entry::Occupied(entry) => claim_use(&entry.get().0),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert((std::sync::atomic::AtomicUsize::new(1), chrono::Utc::now()));
                true
            }
        }
    }

    pub fn deny(&self, id: impl Into<compact_str::CompactString>) {
        let mut denied = self.denied_jtokens.write();
        denied.insert(id.into(), chrono::Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_with_max_uses(max_jwt_uses: usize) -> JwtClient {
        let mut config = crate::config::InnerConfig::default();
        config.api.max_jwt_uses = max_jwt_uses;

        JwtClient::new(&config)
    }

    // JwtClient

    #[test]
    fn limited_jwt_id_allows_up_to_max_uses() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(3);
            assert!(client.limited_jwt_id("token"));
            assert!(client.limited_jwt_id("token"));
            assert!(client.limited_jwt_id("token"));
            assert!(!client.limited_jwt_id("token"));
            // other ids have their own budget
            assert!(client.limited_jwt_id("other"));
        });
    }

    #[test]
    fn limited_jwt_id_zero_means_unlimited() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            for _ in 0..100 {
                assert!(client.limited_jwt_id("token"));
            }
        });
    }

    #[test]
    fn limited_jwt_id_grants_exactly_max_uses_under_contention() {
        tokio_test::block_on(async {
            let client = Arc::new(client_with_max_uses(5));
            let barrier = Arc::new(std::sync::Barrier::new(8));
            let successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            let threads: Vec<_> = (0..8)
                .map(|_| {
                    let client = Arc::clone(&client);
                    let barrier = Arc::clone(&barrier);
                    let successes = Arc::clone(&successes);

                    std::thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..10 {
                            if client.limited_jwt_id("token") {
                                successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                        }
                    })
                })
                .collect();
            for thread in threads {
                thread.join().unwrap();
            }

            assert_eq!(successes.load(std::sync::atomic::Ordering::SeqCst), 5);
        });
    }
}
