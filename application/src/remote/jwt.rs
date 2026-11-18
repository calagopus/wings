use compact_str::ToCompactString;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

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

    /// The API key the token was issued through, `None` for a session.
    pub credential: Option<uuid::Uuid>,
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

        if let Some(issued) = self.issued_at
            && issued.saturating_mul(1000)
                <= client.revocations.read().revoked_at(
                    self.subject.as_deref().and_then(|s| s.parse().ok()),
                    self.credential,
                )
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

/// Panel times, in unix milliseconds, at or before which tokens are revoked.
struct Revocations {
    subjects: HashMap<uuid::Uuid, i64>,
    credentials: HashMap<uuid::Uuid, i64>,
    /// Raised to every pruned revocation, so tokens it covered stay revoked.
    revoked_all: i64,
}

impl Default for Revocations {
    fn default() -> Self {
        Self {
            subjects: HashMap::new(),
            credentials: HashMap::new(),
            revoked_all: i64::MIN,
        }
    }
}

impl Revocations {
    fn revoked_at(&self, subject: Option<uuid::Uuid>, credential: Option<uuid::Uuid>) -> i64 {
        let get = |revoked: &HashMap<uuid::Uuid, i64>, id: Option<uuid::Uuid>| {
            id.and_then(|id| revoked.get(&id).copied())
                .unwrap_or(i64::MIN)
        };

        get(&self.subjects, subject)
            .max(get(&self.credentials, credential))
            .max(self.revoked_all)
    }

    fn prune(&mut self, cutoff: i64) {
        let mut revoked_all = self.revoked_all;
        for revoked in [&mut self.subjects, &mut self.credentials] {
            revoked.retain(|_, &mut revoked_at| {
                let keep = revoked_at > cutoff;
                if !keep {
                    revoked_all = revoked_all.max(revoked_at);
                }

                keep
            });
        }

        self.revoked_all = revoked_all;
    }
}

pub struct JwtClient {
    pub decoding_key: DecodingKey,
    pub validation: Validation,
    pub boot_time: chrono::DateTime<chrono::Utc>,
    pub max_jwt_uses: usize,

    pub denied_jtokens:
        Arc<RwLock<HashMap<compact_str::CompactString, chrono::DateTime<chrono::Utc>>>>,
    pub seen_jtoken_ids: Arc<RwLock<CountingMap>>,

    revocations: Arc<RwLock<Revocations>>,
    revocation_sender: tokio::sync::broadcast::Sender<()>,
}

impl JwtClient {
    pub fn new(config: &crate::config::InnerConfig) -> Result<Self, jsonwebtoken::errors::Error> {
        let denied_jtokens = Arc::new(RwLock::new(HashMap::new()));
        let seen_jtoken_ids = Arc::new(RwLock::new(HashMap::new()));
        let revocations = Arc::new(RwLock::new(Revocations::default()));

        tokio::spawn({
            let denied_jtokens = Arc::clone(&denied_jtokens);
            let seen_jtoken_ids = Arc::clone(&seen_jtoken_ids);
            let revocations = Arc::clone(&revocations);

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

                    revocations.write().prune(
                        (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp_millis(),
                    );
                }
            }
        });

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        Ok(Self {
            decoding_key: DecodingKey::from_secret(config.token.as_bytes())?,
            validation,
            boot_time: chrono::Utc::now(),
            max_jwt_uses: config.api.max_jwt_uses,

            denied_jtokens,
            seen_jtoken_ids,
            revocations,
            revocation_sender: tokio::sync::broadcast::channel(16).0,
        })
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

    /// Revokes the tokens issued to `subjects` (users) or through `credentials` (API keys) at
    /// or before `as_of`, a panel time in unix milliseconds.
    pub fn revoke(
        &self,
        subjects: &HashSet<uuid::Uuid>,
        credentials: &HashSet<uuid::Uuid>,
        as_of: i64,
    ) {
        if subjects.is_empty() && credentials.is_empty() {
            return;
        }

        let mut revocations = self.revocations.write();
        let Revocations {
            subjects: revoked_subjects,
            credentials: revoked_credentials,
            ..
        } = &mut *revocations;
        for (revoked, ids) in [
            (revoked_subjects, subjects),
            (revoked_credentials, credentials),
        ] {
            for &id in ids {
                let revoked_at = revoked.entry(id).or_insert(as_of);
                *revoked_at = (*revoked_at).max(as_of);
            }
        }
        drop(revocations);

        self.revocation_sender.send(()).ok();
    }

    /// Notified after every [`Self::revoke`], so long-lived holders of a token re-validate it.
    pub fn subscribe_revocations(&self) -> tokio::sync::broadcast::Receiver<()> {
        self.revocation_sender.subscribe()
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

    fn payload(subject: Option<&str>, credential: Option<uuid::Uuid>, iat: i64) -> BasePayload {
        BasePayload {
            scope: Default::default(),
            issuer: "panel".into(),
            subject: subject.map(Into::into),
            audience: Vec::new(),
            expiration_time: Some(iat + 600),
            not_before: None,
            issued_at: Some(iat),
            jwt_id: uuid::Uuid::new_v4().to_compact_string(),
            credential,
        }
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

    #[test]
    fn revoke_notifies_subscribers_only_when_non_empty() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let mut revocations = client.subscribe_revocations();

            client.revoke(
                &HashSet::new(),
                &HashSet::new(),
                crate::server::permissions::now_millis(),
            );
            assert!(revocations.try_recv().is_err());

            client.revoke(
                &HashSet::from([uuid::Uuid::new_v4()]),
                &HashSet::new(),
                crate::server::permissions::now_millis(),
            );
            assert!(revocations.try_recv().is_ok());
        });
    }

    // BasePayload

    #[test]
    fn validate_denies_revoked_subject_at_or_before_revocation() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4();
            let token = payload(Some(&user.to_string()), None, iat);
            assert!(token.validate(&client, None).is_ok());

            client.revoke(&HashSet::from([user]), &HashSet::new(), iat * 1000);
            assert!(matches!(
                token.validate(&client, None),
                Err(JwtValidateError::Denied)
            ));

            let other = payload(Some(&uuid::Uuid::new_v4().to_string()), None, iat);
            assert!(other.validate(&client, None).is_ok());
        });
    }

    #[test]
    fn validate_denies_revoked_credential_at_or_before_revocation() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4().to_string();
            let key = uuid::Uuid::new_v4();
            client.revoke(&HashSet::new(), &HashSet::from([key]), iat * 1000);

            assert!(matches!(
                payload(Some(&user), Some(key), iat).validate(&client, None),
                Err(JwtValidateError::Denied)
            ));
            // the same user through a session or a different key is unaffected
            assert!(
                payload(Some(&user), None, iat)
                    .validate(&client, None)
                    .is_ok()
            );
            assert!(
                payload(Some(&user), Some(uuid::Uuid::new_v4()), iat)
                    .validate(&client, None)
                    .is_ok()
            );
        });
    }

    #[test]
    fn validate_accepts_token_issued_after_revocation() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4();
            let key = uuid::Uuid::new_v4();
            client.revoke(
                &HashSet::from([user]),
                &HashSet::from([key]),
                (iat - 1) * 1000,
            );

            assert!(
                payload(Some(&user.to_string()), Some(key), iat)
                    .validate(&client, None)
                    .is_ok()
            );
        });
    }

    #[test]
    fn validate_ignores_revocation_for_non_uuid_subject() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            client.revoke(
                &HashSet::from([uuid::Uuid::nil()]),
                &HashSet::new(),
                iat * 1000,
            );

            assert!(
                payload(Some("not-a-uuid"), None, iat)
                    .validate(&client, None)
                    .is_ok()
            );
        });
    }

    #[test]
    fn validate_older_revocation_does_not_reopen_window() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4();
            let key = uuid::Uuid::new_v4();
            client.revoke(&HashSet::from([user]), &HashSet::from([key]), iat * 1000);
            client.revoke(
                &HashSet::from([user]),
                &HashSet::from([key]),
                (iat - 10) * 1000,
            );

            assert!(matches!(
                payload(Some(&user.to_string()), None, iat).validate(&client, None),
                Err(JwtValidateError::Denied)
            ));
            assert!(matches!(
                payload(None, Some(key), iat).validate(&client, None),
                Err(JwtValidateError::Denied)
            ));
        });
    }

    #[test]
    fn validate_denies_revoked_token_after_prune() {
        tokio_test::block_on(async {
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4();
            let key = uuid::Uuid::new_v4();

            let subject_client = client_with_max_uses(0);
            subject_client.revoke(&HashSet::from([user]), &HashSet::new(), iat * 1000);
            subject_client.revocations.write().prune(iat * 1000);
            assert!(matches!(
                payload(Some(&user.to_string()), None, iat).validate(&subject_client, None),
                Err(JwtValidateError::Denied)
            ));

            let credential_client = client_with_max_uses(0);
            credential_client.revoke(&HashSet::new(), &HashSet::from([key]), iat * 1000);
            credential_client.revocations.write().prune(iat * 1000);
            assert!(matches!(
                payload(None, Some(key), iat).validate(&credential_client, None),
                Err(JwtValidateError::Denied)
            ));
        });
    }

    #[test]
    fn validate_accepts_token_issued_after_pruned_revocation() {
        tokio_test::block_on(async {
            let client = client_with_max_uses(0);
            let iat = chrono::Utc::now().timestamp();
            let user = uuid::Uuid::new_v4();
            let key = uuid::Uuid::new_v4();
            client.revoke(
                &HashSet::from([user]),
                &HashSet::from([key]),
                (iat - 1) * 1000,
            );
            client.revocations.write().prune(iat * 1000);

            assert!(
                payload(Some(&user.to_string()), Some(key), iat)
                    .validate(&client, None)
                    .is_ok()
            );
        });
    }
}
