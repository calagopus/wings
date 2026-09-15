use crate::routes::ApiError;
use accept_header::Accept;
use axum::response::IntoResponse;
use std::str::FromStr;

pub type ApiResponseResult = Result<ApiResponse, ApiResponse>;

tokio::task_local! {
    pub static ACCEPT_HEADER: Option<Accept>;
}

pub fn accept_from_headers(headers: &axum::http::HeaderMap) -> Option<Accept> {
    let header_value = headers.get(axum::http::header::ACCEPT)?;
    let header_str = header_value.to_str().ok()?;

    Accept::from_str(header_str).ok()
}

pub struct ApiResponse {
    pub body: axum::body::Body,
    pub status: axum::http::StatusCode,
    pub headers: axum::http::HeaderMap,
}

impl ApiResponse {
    #[inline]
    pub fn new(body: axum::body::Body) -> Self {
        Self {
            body,
            status: axum::http::StatusCode::OK,
            headers: axum::http::HeaderMap::new(),
        }
    }

    #[inline]
    pub fn new_stream(stream: impl tokio::io::AsyncRead + Send + 'static) -> Self {
        Self {
            body: axum::body::Body::from_stream(tokio_util::io::ReaderStream::with_capacity(
                stream,
                crate::BUFFER_SIZE,
            )),
            status: axum::http::StatusCode::OK,
            headers: axum::http::HeaderMap::new(),
        }
    }

    pub fn new_serialized(body: impl serde::Serialize) -> Self {
        Self::new_serialized_with_capacity(body, 128)
    }

    pub fn new_serialized_with_capacity(body: impl serde::Serialize, capacity: usize) -> Self {
        let accept_header = ACCEPT_HEADER.try_with(|h| h.clone()).ok().flatten();

        const AVAILABLE_SERIALIZERS: &[mime::Mime] =
            &[mime::APPLICATION_JSON, mime::APPLICATION_MSGPACK];

        let negotiated = accept_header
            .as_ref()
            .and_then(|accept| accept.negotiate(AVAILABLE_SERIALIZERS).ok())
            .unwrap_or(mime::APPLICATION_JSON);

        let (content_type, body) = match negotiated {
            m if m.essence_str() == mime::APPLICATION_MSGPACK.essence_str() => {
                let mut bytes = Vec::new();
                let mut se = rmp_serde::Serializer::new(&mut bytes)
                    .with_struct_map()
                    .with_human_readable();
                if let Err(err) = body.serialize(&mut se) {
                    tracing::error!(
                        "failed to serialize response body to MessagePack: {:?}",
                        err
                    );

                    (
                        axum::http::HeaderValue::from_static("application/json"),
                        axum::body::Body::from("{}"),
                    )
                } else {
                    (
                        axum::http::HeaderValue::from_static("application/msgpack"),
                        axum::body::Body::from(bytes),
                    )
                }
            }
            _ => {
                let mut bytes = Vec::with_capacity(capacity);
                if let Err(err) = serde_json::to_writer(&mut bytes, &body) {
                    tracing::error!("failed to serialize response body to JSON: {:?}", err);
                    bytes = b"{}".to_vec();
                }

                (
                    axum::http::HeaderValue::from_static("application/json"),
                    axum::body::Body::from(bytes),
                )
            }
        };

        Self {
            body,
            status: axum::http::StatusCode::OK,
            headers: axum::http::HeaderMap::from_iter([
                (axum::http::header::CONTENT_TYPE, content_type),
                (
                    axum::http::header::VARY,
                    axum::http::HeaderValue::from_static("Accept"),
                ),
            ]),
        }
    }

    #[inline]
    pub fn error(err: &str) -> Self {
        Self::new_serialized(ApiError::new(err)).with_status(axum::http::StatusCode::BAD_REQUEST)
    }

    #[inline]
    pub fn with_status(mut self, status: axum::http::StatusCode) -> Self {
        self.status = status;
        self
    }

    #[inline]
    pub fn with_headers(mut self, headers: axum::http::HeaderMap) -> Self {
        self.headers = headers;
        self
    }

    #[inline]
    pub fn with_header(mut self, key: &'static str, value: &str) -> Self {
        if let Ok(header_value) = axum::http::HeaderValue::from_str(value) {
            self.headers.insert(key, header_value);
        }

        self
    }

    #[inline]
    pub fn ok(self) -> ApiResponseResult {
        Ok(self)
    }
}

impl<T> From<T> for ApiResponse
where
    T: Into<anyhow::Error>,
{
    fn from(err: T) -> Self {
        let err = err.into();

        tracing::error!("a request error occurred: {:?}", err);

        let message = if let Some(err) = err.downcast_ref::<&str>() {
            err.to_string()
        } else if let Some(err) = err.downcast_ref::<String>() {
            err.to_string()
        } else if let Some(err) = err.downcast_ref::<std::io::Error>() {
            err.to_string()
        } else if let Some(err) = err.downcast_ref::<zip::result::ZipError>() {
            match err {
                zip::result::ZipError::Io(err) => err.to_string(),
                _ => err.to_string(),
            }
        } else if let Some(err) = err.downcast_ref::<sevenz_rust2::Error>() {
            match err {
                sevenz_rust2::Error::Io(err, _) => err.to_string(),
                _ => err.to_string(),
            }
        } else {
            "internal server error".to_string()
        };

        ApiResponse::error(&message).with_status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for ApiResponse {
    #[inline]
    fn into_response(self) -> axum::response::Response {
        let mut response = axum::http::Response::new(self.body);
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;

        response
    }
}
