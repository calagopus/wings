use rustls::{
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use std::{io, sync::Arc};

pub async fn server_config(cert: &str, key: &str, ktls: bool) -> io::Result<Arc<ServerConfig>> {
    let (cert, key) = (cert.to_owned(), key.to_owned());

    tokio::task::spawn_blocking(move || {
        let certs = CertificateDer::pem_file_iter(&cert)
            .map_err(|err| io::Error::other(format!("failed to read ssl certificate: {err}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| io::Error::other(format!("failed to parse ssl certificate: {err}")))?;
        let key = PrivateKeyDer::from_pem_file(&key)
            .map_err(|err| io::Error::other(format!("failed to read ssl key: {err}")))?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| io::Error::other(format!("failed to build ssl config: {err}")))?;

        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.enable_secret_extraction = ktls;

        Ok(Arc::new(config))
    })
    .await
    .map_err(io::Error::other)?
}

#[cfg(target_os = "linux")]
pub use ktls::*;

#[cfg(target_os = "linux")]
mod ktls {
    use ::ktls::{CompatibleCiphers, CorkStream, KtlsStream};
    use axum_server::{accept::Accept, tls_rustls::RustlsConfig};
    use std::{
        future::Future,
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::TcpStream,
    };
    use tokio_rustls::server::TlsStream;

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

    pub async fn detect_ktls_support() -> Option<Arc<CompatibleCiphers>> {
        let ciphers = match tokio::time::timeout(PROBE_TIMEOUT, CompatibleCiphers::new()).await {
            Ok(Ok(ciphers)) => ciphers,
            Ok(Err(err)) => {
                tracing::warn!("failed to probe kernel tls support: {:#?}", err);

                return None;
            }
            Err(_) => {
                tracing::warn!("timed out probing kernel tls support");

                return None;
            }
        };

        let supported = [
            ("TLS1.2 AES-GCM-128", ciphers.tls12.aes_gcm_128),
            ("TLS1.2 AES-GCM-256", ciphers.tls12.aes_gcm_256),
            ("TLS1.2 CHACHA20-POLY1305", ciphers.tls12.chacha20_poly1305),
            ("TLS1.3 AES-GCM-128", ciphers.tls13.aes_gcm_128),
            ("TLS1.3 AES-GCM-256", ciphers.tls13.aes_gcm_256),
            ("TLS1.3 CHACHA20-POLY1305", ciphers.tls13.chacha20_poly1305),
        ];

        let names: Vec<&str> = supported
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(name, _)| *name)
            .collect();

        if names.is_empty() {
            tracing::warn!("kernel tls is not supported by this kernel, using userspace tls");

            return None;
        }

        tracing::info!("kernel tls enabled (ciphers: {})", names.join(", "));

        Some(Arc::new(ciphers))
    }

    #[derive(Clone)]
    pub struct KtlsAcceptor {
        config: RustlsConfig,
        ciphers: Arc<CompatibleCiphers>,
    }

    impl KtlsAcceptor {
        pub fn new(config: RustlsConfig, ciphers: Arc<CompatibleCiphers>) -> Self {
            Self { config, ciphers }
        }
    }

    impl<S: Send + 'static> Accept<TcpStream, S> for KtlsAcceptor {
        type Stream = MaybeKtlsStream;
        type Service = S;
        type Future =
            Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

        fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
            let acceptor = tokio_rustls::TlsAcceptor::from(self.config.get_inner());
            let ciphers = Arc::clone(&self.ciphers);

            Box::pin(async move {
                let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
                    let stream = acceptor.accept(CorkStream::new(stream)).await?;

                    let suite = stream.get_ref().1.negotiated_cipher_suite();
                    if !suite.is_some_and(|suite| ciphers.is_compatible(suite)) {
                        tracing::debug!(
                            "negotiated cipher suite ({:?}) is not kernel tls compatible, using userspace tls",
                            suite.map(|suite| suite.suite())
                        );

                        return Ok(MaybeKtlsStream::Rustls(Box::new(stream)));
                    }

                    match ::ktls::config_ktls_server(stream).await {
                        Ok(stream) => Ok(MaybeKtlsStream::Ktls(stream)),
                        Err(err) => Err(io::Error::other(format!(
                            "failed to hand connection off to kernel tls: {err}"
                        ))),
                    }
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out"));

                let stream = match stream {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(err)) | Err(err) => {
                        tracing::debug!("failed to accept https connection: {:#?}", err);

                        return Err(err);
                    }
                };

                Ok((stream, service))
            })
        }
    }

    impl std::fmt::Debug for KtlsAcceptor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("KtlsAcceptor").finish_non_exhaustive()
        }
    }

    pub enum MaybeKtlsStream {
        Ktls(KtlsStream<TcpStream>),
        Rustls(Box<TlsStream<CorkStream<TcpStream>>>),
    }

    impl AsyncRead for MaybeKtlsStream {
        #[inline]
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Ktls(stream) => Pin::new(stream).poll_read(cx, buf),
                Self::Rustls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for MaybeKtlsStream {
        #[inline]
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Ktls(stream) => Pin::new(stream).poll_write(cx, buf),
                Self::Rustls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
            }
        }

        #[inline]
        fn poll_write_vectored(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bufs: &[io::IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            match self.get_mut() {
                Self::Ktls(stream) => Pin::new(stream.get_mut()).poll_write_vectored(cx, bufs),
                Self::Rustls(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
            }
        }

        #[inline]
        fn is_write_vectored(&self) -> bool {
            match self {
                Self::Ktls(stream) => stream.get_ref().is_write_vectored(),
                Self::Rustls(stream) => stream.is_write_vectored(),
            }
        }

        #[inline]
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Ktls(stream) => Pin::new(stream).poll_flush(cx),
                Self::Rustls(stream) => Pin::new(&mut **stream).poll_flush(cx),
            }
        }

        #[inline]
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.get_mut() {
                Self::Ktls(stream) => Pin::new(stream).poll_shutdown(cx),
                Self::Rustls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
            }
        }
    }
}
