use compact_str::CompactString;

#[derive(Debug)]
pub enum PbsError {
    Config(CompactString),
    Unauthorized {
        token_id: CompactString,
    },
    Forbidden {
        datastore: CompactString,
    },
    NotFound {
        datastore: CompactString,
    },
    FingerprintMismatch {
        expected: CompactString,
        actual: CompactString,
    },
    Http {
        status: u16,
        message: CompactString,
    },
    Transport(CompactString),
    Decode(CompactString),
}

impl std::fmt::Display for PbsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PbsError::Config(msg) => write!(f, "invalid PBS configuration: {msg}"),
            PbsError::Unauthorized { token_id } => write!(
                f,
                "PBS rejected the API token (HTTP 401); verify the token id and secret for '{token_id}'"
            ),
            PbsError::Forbidden { datastore } => write!(
                f,
                "PBS denied access (HTTP 403); the token likely lacks the required datastore ACL (DatastoreAudit/DatastoreBackup) on '{datastore}'"
            ),
            PbsError::NotFound { datastore } => write!(
                f,
                "PBS datastore or namespace not found (HTTP 404) for datastore '{datastore}'"
            ),
            PbsError::FingerprintMismatch { expected, actual } => write!(
                f,
                "PBS TLS certificate fingerprint mismatch: expected {expected}, server presented {actual}"
            ),
            PbsError::Http { status, message } => {
                write!(f, "PBS returned HTTP {status}: {message}")
            }
            PbsError::Transport(msg) => write!(f, "failed to reach PBS: {msg}"),
            PbsError::Decode(msg) => write!(f, "failed to parse PBS response: {msg}"),
        }
    }
}

impl std::error::Error for PbsError {}

impl PbsError {
    pub(super) fn transport(err: reqwest::Error) -> Self {
        PbsError::Transport(err.to_string().into())
    }
}
