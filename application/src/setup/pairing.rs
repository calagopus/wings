use colored::Colorize;
use hmac::{Hmac, KeyInit, Mac};
use rand::seq::IndexedRandom;
use sha2::Sha256;

const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LENGTH: usize = 8;
const MAX_FAILURES: usize = 5;

pub const SIGNATURE_HEADER: &str = "X-Pairing-Signature";

fn generate() -> String {
    (0..CODE_LENGTH)
        .filter_map(|_| ALPHABET.choose(&mut rand::rng()).copied().map(char::from))
        .collect()
}

fn display(code: &str) -> String {
    let (first, second) = code.split_at(CODE_LENGTH / 2);
    format!("{first}-{second}")
}

fn signing_mac(code: &str, method: &str, path: &str, body: &[u8]) -> Hmac<Sha256> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(code.as_bytes()).expect("hmac accepts keys of any length");
    mac.update(method.as_bytes());
    mac.update(b"\n");
    mac.update(path.as_bytes());
    mac.update(b"\n");
    mac.update(body);

    mac
}

pub struct Pairing {
    code: String,
    failures: usize,
}

impl Pairing {
    pub fn new() -> Self {
        let pairing = Self {
            code: generate(),
            failures: 0,
        };
        pairing.print("pairing code");

        pairing
    }

    fn print(&self, label: &str) {
        println!("{label}: {}", display(&self.code).bold().green());
    }

    pub fn verify(
        &mut self,
        method: &str,
        path: &str,
        signature: Option<&str>,
        body: &[u8],
    ) -> bool {
        let valid = signature
            .and_then(|signature| hex::decode(signature).ok())
            .is_some_and(|signature| {
                signing_mac(&self.code, method, path, body)
                    .verify_slice(&signature)
                    .is_ok()
            });

        if valid {
            return true;
        }

        self.failures += 1;
        eprintln!(
            "{}",
            format!(
                "rejected a pairing request with an invalid code ({}/{MAX_FAILURES})",
                self.failures
            )
            .yellow()
        );

        if self.failures >= MAX_FAILURES {
            self.code = generate();
            self.failures = 0;
            self.print("too many failed attempts, new pairing code");
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_CODE: &str = "ABCD2345";
    const KNOWN_BODY: &[u8] = br#"{"code":"x"}"#;
    const KNOWN_SIGNATURE: &str =
        "f1e766580abcfd6257d8ef54c8cd7d09e3a01132dead1deb853b3a2fdb1dc307";

    fn pairing() -> Pairing {
        Pairing {
            code: KNOWN_CODE.into(),
            failures: 0,
        }
    }

    fn verify_known(pairing: &mut Pairing, signature: Option<&str>) -> bool {
        pairing.verify("POST", "/setup/enroll", signature, KNOWN_BODY)
    }

    // Pairing
    #[test]
    fn accepts_known_answer_signature() {
        let mut pairing = pairing();

        assert!(verify_known(&mut pairing, Some(KNOWN_SIGNATURE)));
        assert_eq!(pairing.failures, 0);
        assert_eq!(pairing.code, KNOWN_CODE);
    }

    #[test]
    fn rejects_missing_malformed_and_wrong_signatures() {
        let mut flipped = KNOWN_SIGNATURE.to_string();
        flipped.replace_range(0..1, "0");

        assert!(!verify_known(&mut pairing(), None));
        assert!(!verify_known(&mut pairing(), Some("")));
        assert!(!verify_known(&mut pairing(), Some("not hex at all")));
        assert!(!verify_known(&mut pairing(), Some(&flipped)));
        assert!(!verify_known(
            &mut pairing(),
            Some(&KNOWN_SIGNATURE[..KNOWN_SIGNATURE.len() - 2])
        ));
        assert!(!pairing().verify("POST", "/setup/probe", Some(KNOWN_SIGNATURE), KNOWN_BODY));
        assert!(!pairing().verify("GET", "/setup/enroll", Some(KNOWN_SIGNATURE), KNOWN_BODY));
        assert!(!pairing().verify(
            "POST",
            "/setup/enroll",
            Some(KNOWN_SIGNATURE),
            br#"{"code":"y"}"#
        ));
    }

    #[test]
    fn code_survives_fewer_than_max_failures() {
        let mut pairing = pairing();
        for _ in 0..MAX_FAILURES - 1 {
            assert!(!verify_known(&mut pairing, None));
        }

        assert!(verify_known(&mut pairing, Some(KNOWN_SIGNATURE)));
    }

    #[test]
    fn code_rotates_after_max_failures() {
        let mut pairing = pairing();
        for _ in 0..MAX_FAILURES {
            assert!(!verify_known(&mut pairing, None));
        }

        assert_ne!(pairing.code, KNOWN_CODE);
        assert_eq!(pairing.code.len(), CODE_LENGTH);
        assert_eq!(pairing.failures, 0);
        assert!(!verify_known(&mut pairing, Some(KNOWN_SIGNATURE)));
    }
}
