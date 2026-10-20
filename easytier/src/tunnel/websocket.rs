use super::FromUrl;
use crate::tunnel::common::bind;
use crate::{proto::common::TunnelInfo, socket::tcp::RuntimeTcpSocket};
use anyhow::Context as _;
use base64::Engine as _;
use bytes::BytesMut;
use cidr::IpCidr;
use easytier_core::{
    packet::{ZCPacket, ZCPacketType},
    socket::tcp::VirtualTcpSocket,
    tunnel::{IpVersion, Tunnel, TunnelError, wrapper::TunnelWrapper},
};
use forwarded_header_value::ForwardedHeaderValue;
use futures::{Sink, StreamExt};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, net::TcpSocket, time::timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::either::Either;
use tokio_websockets::{ClientBuilder, Limits, MaybeTlsStream, Message, ServerBuilder, WebSocketStream};
use zerocopy::AsBytes as _;

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

static TRUSTED_PROXIES: LazyLock<Vec<IpCidr>> = LazyLock::new(|| {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "::1/128",
        "fc00::/7",
    ]
    .into_iter()
    .map(|cidr| cidr.parse().unwrap())
    .collect()
});

fn trusted_proxy_contains(ip: IpAddr) -> bool {
    TRUSTED_PROXIES.iter().any(|cidr| match (cidr, ip) {
        (IpCidr::V4(cidr), IpAddr::V4(ip)) => cidr.contains(&ip),
        (IpCidr::V6(cidr), IpAddr::V6(ip)) => cidr.contains(&ip),
        _ => false,
    })
}

fn websocket_error(error: impl std::fmt::Display) -> TunnelError {
    TunnelError::ProtocolError(format!("websocket error: {error}"))
}

fn is_wss(url: &url::Url) -> Result<bool, TunnelError> {
    match url.scheme() {
        "ws" | "http" => Ok(false),
        "wss" | "https" => Ok(true),
        scheme => Err(TunnelError::InvalidProtocol(scheme.to_owned())),
    }
}

struct WebSocketPacketSink<S> {
    inner: S,
}

impl<S> WebSocketPacketSink<S> {
    fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, E> Sink<ZCPacket> for WebSocketPacketSink<S>
where
    S: Sink<Message, Error = E> + Unpin,
    E: std::fmt::Display,
{
    type Error = TunnelError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map(|result| result.map_err(websocket_error))
    }

    fn start_send(mut self: Pin<&mut Self>, packet: ZCPacket) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(Message::binary(packet.tunnel_payload_bytes().freeze()))
            .map_err(websocket_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map(|result| result.map_err(websocket_error))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map(|result| result.map_err(websocket_error))
    }
}

async fn map_from_ws_message(
    message: Result<Message, tokio_websockets::Error>,
) -> Option<Result<ZCPacket, TunnelError>> {
    let message = match message {
        Ok(message) => message,
        Err(error) => {
            tracing::error!(?error, "recv from websocket error");
            return Some(Err(websocket_error(error)));
        }
    };
    if message.is_close() {
        tracing::warn!("recv close message from websocket");
        return None;
    }
    if !message.is_binary() {
        let message = format!("{message:?}");
        tracing::error!(?message, "Invalid packet");
        return Some(Err(TunnelError::InvalidPacket(message)));
    }
    Some(Ok(ZCPacket::new_from_buf(
        BytesMut::from(message.into_payload().as_bytes()),
        ZCPacketType::DummyTunnel,
    )))
}

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn get_insecure_tls_client_config() -> rustls::ClientConfig {
    // Library callers may not have initialized a process-wide provider.
    // Use the same explicit backend for TLS and signature verification.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider))
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config
}

fn get_insecure_tls_cert<'a>() -> (
    Vec<rustls::pki_types::CertificateDer<'a>>,
    rustls::pki_types::PrivateKeyDer<'a>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let private_key = cert.signing_key.serialize_der();
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(private_key);
    (vec![cert_der], private_key.into())
}

pub(crate) async fn upgrade_accepted<S>(
    stream: S,
    local_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let peer_addr = stream.peer_addr()?;
    let mut remote_url = socket_url(local_url.scheme(), peer_addr);
    let stream = if is_wss(&local_url)? {
        let (certificates, private_key) = get_insecure_tls_cert();
        // Do not rely on another tunnel initializing the global provider.
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .with_context(|| "Failed to select TLS protocol versions")?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .with_context(|| "Failed to create server config")?;
        Either::Left(TlsAcceptor::from(Arc::new(config)).accept(stream).await?)
    } else {
        Either::Right(stream)
    };

    let (request, stream) = ServerBuilder::new()
        .limits(Limits::unlimited())
        .max_headers(128)
        .accept(stream)
        .await
        .map_err(websocket_error)?;

    if trusted_proxy_contains(peer_addr.ip())
        && let Some(forwarded) = request
            .headers()
            .get("Forwarded")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ForwardedHeaderValue::from_forwarded(value).ok())
            .or_else(|| {
                request
                    .headers()
                    .get("X-Forwarded-For")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| ForwardedHeaderValue::from_x_forwarded_for(value).ok())
            })
        && let Some(ip) = forwarded.remotest_forwarded_for_ip()
    {
        remote_url
            .set_host(Some(&ip.to_string()))
            .map_err(|_| TunnelError::InvalidAddr(format!("invalid forwarded ip {ip}")))?;
        remote_url
            .query_pairs_mut()
            .append_pair("proxy", &peer_addr.to_string());
    }

    let (write, read) = stream.split();
    let remote_url: crate::proto::common::Url = remote_url.into();
    let info = TunnelInfo {
        tunnel_type: local_url.scheme().to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone()),
        resolved_remote_addr: Some(remote_url),
    };
    Ok(Box::new(TunnelWrapper::new(
        read.filter_map(map_from_ws_message),
        WebSocketPacketSink::new(write),
        Some(info),
    )))
}

fn socket_url(scheme: &str, addr: SocketAddr) -> url::Url {
    let mut url = url::Url::parse(&format!("{scheme}://0.0.0.0"))
        .expect("WebSocket transport scheme should be a valid URL scheme");
    url.set_ip_host(addr.ip()).unwrap();
    url.set_port(Some(addr.port())).unwrap();
    url
}

/// Result of a manual WebSocket upgrade attempt.
enum UpgradeOutcome<S> {
    /// Upgrade succeeded, stream is ready for WebSocket frames.
    Success(WebSocketStream<BufferedStream<S>>),
    /// Server returned a redirect (3xx). `location` is the redirect target,
    /// `set_cookies` are the Set-Cookie headers to record.
    Redirect {
        location: String,
        set_cookies: Vec<String>,
    },
}

/// A simple cookie jar that stores cookies as name=value pairs.
#[derive(Debug, Default)]
struct CookieJar {
    cookies: HashMap<String, String>,
}

impl CookieJar {
    /// Parse a Set-Cookie header value and store the cookie.
    fn add_set_cookie(&mut self, header_value: &str) {
        if let Some((name_value, _attrs)) = header_value.split_once(';') {
            if let Some((name, value)) = name_value.split_once('=') {
                self.cookies
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
        } else if let Some((name, value)) = header_value.split_once('=') {
            self.cookies
                .insert(name.trim().to_string(), value.trim().to_string());
        }
    }

    /// Format all stored cookies as a Cookie header value: name1=value1; name2=value2
    fn to_cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Load cookies from a file (one "name=value" per line, or Netscape format).
    fn load_from_file(path: &str) -> Result<Self, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let mut jar = CookieJar::default();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.contains('\t') {
                let fields: Vec<&str> = line.split('\t').collect();
                if fields.len() >= 7 {
                    jar.cookies
                        .insert(fields[5].trim().to_string(), fields[6].trim().to_string());
                }
            } else if let Some((name, value)) = line.split_once('=') {
                jar.cookies
                    .insert(name.trim().to_string(), value.trim().to_string());
            }
        }
        Ok(jar)
    }
}

/// A stream wrapper that prepends leftover bytes (read during HTTP upgrade)
/// back to the front of the underlying stream.
struct BufferedStream<S> {
    inner: S,
    leftover: BytesMut,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BufferedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.leftover.is_empty() {
            let len = self.leftover.len().min(buf.remaining());
            buf.put_slice(&self.leftover[..len]);
            let _ = self.leftover.split_to(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BufferedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Resolve a redirect Location against the current URL.
fn resolve_redirect(current: &url::Url, location: &str) -> Result<url::Url, TunnelError> {
    if location.starts_with("http://") || location.starts_with("https://") {
        location
            .parse()
            .map_err(|_| TunnelError::InvalidAddr(format!("invalid redirect url: {location}")))
    } else {
        current
            .join(location)
            .map_err(|_| TunnelError::InvalidAddr(format!("invalid redirect url: {location}")))
    }
}

/// Manually perform WebSocket HTTP upgrade handshake.
/// Supports HTTP 302 redirects and cookie recording.
async fn manual_ws_upgrade<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    builder: &ClientBuilder<'_>,
    mut stream: S,
    addr: &url::Url,
    cookie_jar: &CookieJar,
) -> Result<UpgradeOutcome<S>, TunnelError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let key = {
        let random_bytes: [u8; 16] = rand::random();
        base64::engine::general_purpose::STANDARD.encode(random_bytes)
    };

    let host = addr.host_str().unwrap_or("");
    let path = addr.path();
    let query = addr.query();
    let path_and_query = match query {
        Some(q) => format!("{}?{}", path, q),
        None => path.to_string(),
    };

    let cookie_header = if cookie_jar.cookies.is_empty() {
        String::new()
    } else {
        format!("Cookie: {}\r\n", cookie_jar.to_cookie_header())
    };

    let request = format!(
        "GET {path_and_query} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         {cookie_header}\
         \r\n"
    );

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(TunnelError::IOError)?;
    stream.flush().await.map_err(TunnelError::IOError)?;

    let mut buf = vec![0u8; 8192];
    let mut total_read = 0;

    let (header_end, status_code, location, set_cookies) = loop {
        if total_read >= buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        let n = stream
            .read(&mut buf[total_read..])
            .await
            .map_err(TunnelError::IOError)?;
        if n == 0 {
            return Err(TunnelError::IOError(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed during WebSocket handshake",
            )));
        }
        total_read += n;

        // Look for the end of HTTP headers: \r\n\r\n
        let header_end = buf[..total_read]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4);

        if let Some(header_end) = header_end {
            let header_block = &buf[..header_end];
            let mut lines = header_block.split(|&b| b == b'\n');

            // Parse status line: HTTP/1.1 <code> <reason>
            let status_code = lines
                .next()
                .and_then(|line| {
                    let mut parts = line.split(|&b| b == b' ');
                    parts.next(); // skip "HTTP/1.1"
                    parts.next().and_then(|code| {
                        std::str::from_utf8(code).ok().and_then(|s| s.trim().parse::<u16>().ok())
                    })
                })
                .unwrap_or(0);

            let mut location = String::new();
            let mut set_cookies: Vec<String> = Vec::new();

            for line in lines {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                if let Some(colon) = line.iter().position(|&b| b == b':') {
                    let name = &line[..colon];
                    let value = &line[colon + 1..];
                    let value_str = String::from_utf8_lossy(value).trim().to_string();
                    if name.eq_ignore_ascii_case(b"Location") {
                        location = value_str;
                    } else if name.eq_ignore_ascii_case(b"Set-Cookie") {
                        set_cookies.push(value_str);
                    }
                }
            }

            break (header_end, status_code, location, set_cookies);
        }
    };

    if (301..=308).contains(&status_code) {
        if location.is_empty() {
            return Err(websocket_error(format!(
                "redirect {status_code} without Location header"
            )));
        }

        if location.contains("account.aliyun.com") {
            tracing::info!(
                "WebSocket upgrade redirected to aliyun login: {}. \
                 Recording {} cookie(s). Set EASYTIER_COOKIE_FILE to authenticate.",
                location,
                set_cookies.len()
            );
        } else {
            tracing::info!("WebSocket upgrade redirected ({status_code}): {location}");
        }

        return Ok(UpgradeOutcome::Redirect {
            location,
            set_cookies,
        });
    }

    if status_code != 101 {
        return Err(websocket_error(format!(
            "server did not switch protocols, status: {status_code}"
        )));
    }

    let leftover = BytesMut::from(&buf[header_end..total_read]);
    let stream = BufferedStream {
        inner: stream,
        leftover,
    };

    Ok(UpgradeOutcome::Success(builder.take_over(stream)))
}

#[derive(Debug)]
pub struct WsTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
}

impl WsTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        self.listener = None;

        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let listener = bind::<TcpListener>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()
            .await?;

        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        loop {
            let listener = self.listener.as_ref().unwrap();
            // only fail on tcp accept error
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true).unwrap();
            match timeout(
                SERVER_HANDSHAKE_TIMEOUT,
                upgrade_accepted(RuntimeTcpSocket::new(stream), self.addr.clone()),
            )
            .await
            {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                e => {
                    tracing::error!(?e, ?self, "Failed to accept ws/wss tunnel");
                    continue;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl easytier_core::socket::SocketListener for WsTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub(crate) async fn upgrade_connected<S>(
    stream: S,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let initial_is_wss = is_wss(&remote_url)?;
    let local_addr = stream.local_addr()?;
    let resolved_remote_addr = stream.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type: remote_url.scheme().to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&local_addr.to_string(), remote_url.scheme()).into(),
        ),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(
                &resolved_remote_addr.to_string(),
                remote_url.scheme(),
            )
            .into(),
        ),
    };

    let mut cookie_jar = if let Ok(path) = std::env::var("EASYTIER_COOKIE_FILE") {
        match CookieJar::load_from_file(&path) {
            Ok(jar) => {
                tracing::info!("Loaded {} cookie(s) from {path}", jar.cookies.len());
                jar
            }
            Err(e) => {
                tracing::warn!("Failed to load cookies from {path}: {e}");
                CookieJar::default()
            }
        }
    } else {
        CookieJar::default()
    };

    let mut current_url = remote_url.clone();
    let initial_stream: MaybeTlsStream<S> = if initial_is_wss {
        let tls = tokio_rustls::TlsConnector::from(Arc::new(get_insecure_tls_client_config()));
        let sni = remote_url.domain().unwrap_or("localhost").to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
        MaybeTlsStream::Rustls(tls.connect(server_name, stream).await?)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    let mut stream: Either<MaybeTlsStream<S>, MaybeTlsStream<RuntimeTcpSocket>> =
        Either::Left(initial_stream);

    const MAX_REDIRECTS: usize = 10;
    for _ in 0..MAX_REDIRECTS {
        let builder =
            ClientBuilder::from_uri(http::Uri::try_from(current_url.to_string()).unwrap())
                .max_headers(128);
        match manual_ws_upgrade(&builder, stream, &current_url, &cookie_jar).await? {
            UpgradeOutcome::Success(client) => {
                let (write, read) = client.split();
                return Ok(Box::new(TunnelWrapper::new(
                    read.filter_map(map_from_ws_message),
                    WebSocketPacketSink::new(write),
                    Some(info),
                )));
            }
            UpgradeOutcome::Redirect {
                location,
                set_cookies,
            } => {
                for cookie in &set_cookies {
                    cookie_jar.add_set_cookie(cookie);
                }
                current_url = resolve_redirect(&current_url, &location)?;
                let new_is_wss = is_wss(&current_url)?;
                let addr = SocketAddr::from_url(current_url.clone(), IpVersion::Both).await?;
                let socket = if addr.is_ipv4() {
                    TcpSocket::new_v4()?
                } else {
                    TcpSocket::new_v6()?
                };
                let tcp_stream = socket.connect(addr).await?;
                let rt_socket = RuntimeTcpSocket::new(tcp_stream);
                let new_stream: MaybeTlsStream<RuntimeTcpSocket> = if new_is_wss {
                    let tls = tokio_rustls::TlsConnector::from(Arc::new(
                        get_insecure_tls_client_config(),
                    ));
                    let sni = current_url.domain().unwrap_or("localhost").to_owned();
                    let server_name = rustls::pki_types::ServerName::try_from(sni)
                        .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
                    MaybeTlsStream::Rustls(tls.connect(server_name, rt_socket).await?)
                } else {
                    MaybeTlsStream::Plain(rt_socket)
                };
                stream = Either::Right(new_stream);
            }
        }
    }
    Err(websocket_error(format!(
        "too many redirects (max {MAX_REDIRECTS})"
    )))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use easytier_core::socket::SocketListener;
    use futures::SinkExt;
    use std::io;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpSocket,
    };

    struct FailingWebSocketSink {
        close_called: bool,
    }

    impl Sink<Message> for FailingWebSocketSink {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> Result<(), Self::Error> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "send failed",
            )))
        }

        fn poll_close(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            self.close_called = true;
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "close failed",
            )))
        }
    }

    #[tokio::test]
    async fn packet_sink_maps_send_and_close_errors_independently() {
        let mut sink = WebSocketPacketSink::new(FailingWebSocketSink {
            close_called: false,
        });

        sink.send(ZCPacket::new_with_payload(b"packet"))
            .await
            .expect_err("send should fail");
        sink.close().await.expect_err("close should fail");
        assert!(sink.inner.close_called);
    }

    #[tokio::test]
    async fn ws_forwarded() {
        let mut listener = WsTunnelListener::new("ws://127.0.0.1:25559".parse().unwrap());
        listener.listen().await.unwrap();

        let server_task = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();

            let remote_addr = tunnel
                .info()
                .unwrap()
                .remote_addr
                .unwrap()
                .url
                .parse::<url::Url>()
                .unwrap();

            assert_eq!(remote_addr.host_str().unwrap(), "203.0.113.5");
            let proxy_addr = remote_addr
                .query_pairs()
                .find(|(k, _)| k == "proxy")
                .map(|(_, v)| v.into_owned())
                .unwrap();
            assert_eq!(proxy_addr, "127.0.0.1:25560");

            tunnel
        });

        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:25560".parse().unwrap()).unwrap();
        let mut stream = socket
            .connect("127.0.0.1:25559".parse().unwrap())
            .await
            .unwrap();

        let handshake = "GET / HTTP/1.1\r\n\
                         Host: 127.0.0.1:25559\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                         Sec-WebSocket-Version: 13\r\n\
                         X-Forwarded-For: 203.0.113.5, 192.168.1.1\r\n\
                         \r\n";

        stream.write_all(handshake.as_bytes()).await.unwrap();

        let mut buf = [0u8; 1024];
        let bytes_read = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..bytes_read]);

        assert!(response.contains("101 Switching Protocols"));

        let _tunnel = server_task.await.unwrap();
    }
}
