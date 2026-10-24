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
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, net::TcpSocket, time::timeout};
use tokio_rustls::TlsAcceptor;
use tokio_util::either::Either;
use tokio_websockets::{
    ClientBuilder, Limits, MaybeTlsStream, Message, ServerBuilder, WebSocketStream,
};
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

/// Whether the browser-driven aliyun login is already running in the background.
/// Stops the outer retry loop from spawning yet another browser window every time
/// CONNECT_TIMEOUT fires.
static LOGIN_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Clears `LOGIN_IN_PROGRESS` even when the login task panics or is cancelled.
struct LoginInProgressGuard;

impl Drop for LoginInProgressGuard {
    fn drop(&mut self) {
        LOGIN_IN_PROGRESS.store(false, Ordering::Relaxed);
    }
}

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

    /// Persist the cookies as one "name=value" per line.
    fn save_to_file(&self, path: &std::path::Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let body = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, body)
    }

    /// Whether the jar already carries an authenticated aliyun DSW session.
    /// We only trust cookies that were set on the gateway domain itself, which
    /// means the full OAuth callback round-trip completed — cookies captured
    /// on `account.aliyun.com` alone are useless.
    fn has_login_session(&self) -> bool {
        self.cookies.contains_key("login_aliyunid_ticket")
            || self.cookies.contains_key("login_aliyunid_pk")
            || self.cookies.contains_key("cookie2")
    }
}

/// Where harvested cookies are stored; `EASYTIER_COOKIE_FILE` wins if set.
fn cookie_file_path() -> std::path::PathBuf {
    std::env::var("EASYTIER_COOKIE_FILE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("easytier-aliyun-cookies.txt"))
}

fn is_aliyun_login_url(url: &str) -> bool {
    url.contains("account.aliyun.com")
}

/// A browser login is launched at most once per this window, tracked on disk so
/// that a failed or abandoned login does not reopen a window on every reconnect
/// retry (the connector retries every second) nor after a process restart.
const LOGIN_RETRY_COOLDOWN: Duration = Duration::from_secs(600);

fn login_marker_path(cookie_file: &std::path::Path) -> std::path::PathBuf {
    let mut name = cookie_file.as_os_str().to_owned();
    name.push(".attempted");
    std::path::PathBuf::from(name)
}

fn login_recently_attempted(cookie_file: &std::path::Path) -> bool {
    std::fs::metadata(login_marker_path(cookie_file))
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|mtime| mtime.elapsed().ok())
        .is_some_and(|age| age < LOGIN_RETRY_COOLDOWN)
}

fn mark_login_attempted(cookie_file: &std::path::Path) {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    if let Err(e) = std::fs::write(login_marker_path(cookie_file), seconds.to_string()) {
        tracing::debug!("cannot write the aliyun login marker: {e}");
    }
}

fn free_local_port() -> Result<u16, TunnelError> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| websocket_error(format!("cannot reserve a local port: {e}")))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| websocket_error(format!("cannot read the reserved port: {e}")))
}

/// Launch a Chromium-based browser with remote debugging enabled, so that the
/// cookies of the login flow can be read afterwards.
fn launch_browser(login_url: &str, port: u16) -> Result<std::process::Child, TunnelError> {
    use std::process::{Command, Stdio};

    let profile = std::env::temp_dir().join(format!("easytier-login-{}", std::process::id()));
    let args = [
        format!("--remote-debugging-port={port}"),
        format!("--user-data-dir={}", profile.display()),
        "--no-first-run".to_owned(),
        "--no-default-browser-check".to_owned(),
        login_url.to_owned(),
    ];

    let mut candidates = Vec::new();
    if let Ok(browser) = std::env::var("EASYTIER_BROWSER") {
        candidates.push(browser);
    }
    candidates.extend(
        [
            "microsoft-edge",
            "microsoft-edge-stable",
            "microsoft-edge-beta",
            "microsoft-edge-dev",
            "msedge",
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "brave-browser",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        .map(str::to_owned),
    );
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        candidates.push(format!(
            r"{local_app_data}\Microsoft\Edge\Application\msedge.exe"
        ));
    }

    for candidate in candidates {
        if let Ok(child) = Command::new(&candidate)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            tracing::info!("Opened {candidate} for the aliyun login");
            return Ok(child);
        }
    }

    Err(websocket_error(
        "no Chromium-based browser found, set EASYTIER_BROWSER to the browser executable"
            .to_owned(),
    ))
}

async fn http_get_local(port: u16, path: &str) -> Result<String, TunnelError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| websocket_error(format!("devtools endpoint is not ready: {e}")))?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(TunnelError::IOError)?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(TunnelError::IOError)?;
    let response = String::from_utf8_lossy(&buf).into_owned();
    Ok(response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default())
}

/// Pop up a browser window for the user to sign in, letting the browser follow
/// the full OAuth 302 chain itself (so that the callback sets cookies on the
/// gateway domain), then harvest those cookies through the Chromium DevTools
/// protocol and store them on disk.
///
/// `entry_url` should be the original protected endpoint (e.g. the wss URL we
/// failed to connect to), not the 302 redirect target — the latter only takes
/// us to the login page, missing the OAuth callback that writes the real
/// gateway session cookie.
async fn interactive_login(
    entry_url: &url::Url,
    cookie_file: &std::path::Path,
) -> Result<CookieJar, TunnelError> {
    use futures::{SinkExt, StreamExt};

    // Open the HTTP(S) counterpart of the wss:// URL so that the browser
    // follows the 302 chain all the way through the OAuth callback.
    let browser_url = {
        let mut u = entry_url.clone();
        match u.scheme() {
            "wss" => {
                u.set_scheme("https").map_err(|_| {
                    TunnelError::InvalidProtocol("cannot switch wss to https".into())
                })?;
            }
            "ws" => {
                u.set_scheme("http")
                    .map_err(|_| TunnelError::InvalidProtocol("cannot switch ws to http".into()))?;
            }
            _ => {} // already http/https, use as-is
        }
        u.to_string()
    };

    let port = free_local_port()?;
    let mut child = launch_browser(&browser_url, port)?;

    // Wait for the devtools endpoint of the freshly started browser.
    let mut websocket_url = None;
    for _ in 0..100 {
        if let Ok(body) = http_get_local(port, "/json/version").await
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(url) = value["webSocketDebuggerUrl"].as_str()
        {
            websocket_url = Some(url.to_owned());
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let websocket_url = websocket_url.ok_or_else(|| {
        websocket_error("the browser did not expose a devtools endpoint".to_owned())
    })?;

    let uri = http::Uri::try_from(websocket_url.clone())
        .map_err(|e| websocket_error(format!("invalid devtools url {websocket_url}: {e}")))?;
    let (mut ws, _) = ClientBuilder::from_uri(uri)
        .connect()
        .await
        .map_err(|e| websocket_error(format!("cannot reach the browser devtools: {e}")))?;

    let wait_secs: u64 = std::env::var("EASYTIER_LOGIN_TIMEOUT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300);
    tracing::info!("Waiting up to {wait_secs}s for the aliyun login to finish");

    // Detect completion by watching the tab URLs: the OAuth flow goes
    // gateway -> account.aliyun.com/login -> gateway (the oauth_callback).
    // Returning to the gateway host means the callback already ran and the
    // session cookie is set. Note the final page usually renders
    // "upstream connect error ... protocol error": the /ide/proxy/<port>/ path
    // only speaks WebSocket, so a plain browser GET always errors out upstream.
    // That page is harmless — authentication has already succeeded by then.
    let entry_host = entry_url.host_str().unwrap_or_default().to_owned();
    let mut saw_login_page = false;
    let mut logged_in = false;
    for _ in 0..wait_secs {
        if let Ok(body) = http_get_local(port, "/json/list").await
            && let Ok(targets) = serde_json::from_str::<serde_json::Value>(&body)
        {
            for target in targets.as_array().into_iter().flatten() {
                if target["type"].as_str() != Some("page") {
                    continue;
                }
                let page_url = target["url"].as_str().unwrap_or_default();
                if page_url.is_empty() || page_url.starts_with("chrome-error://") {
                    continue;
                }
                if page_url.contains(&entry_host) {
                    if saw_login_page {
                        logged_in = true;
                        break;
                    }
                } else {
                    saw_login_page = true;
                }
            }
        }
        if logged_in {
            tracing::info!("aliyun login finished, harvesting cookies");
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    if !logged_in {
        let _ = child.kill();
        return Err(websocket_error(format!(
            "aliyun login did not complete within {wait_secs}s"
        )));
    }

    // Let the callback response settle before reading the cookie store.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Harvest every aliyun cookie. The gateway validates the ticket server-side,
    // so the parent-domain `.aliyun.com` cookies are exactly what it expects.
    let mut jar = CookieJar::default();
    let mut method = "Storage.getCookies";
    for _ in 0..3 {
        let payload = format!("{{\"id\":1,\"method\":\"{method}\"}}");
        if ws.send(Message::text(payload)).await.is_err() {
            break;
        }

        let mut switch_method = false;
        while let Ok(Some(Ok(message))) =
            tokio::time::timeout(Duration::from_secs(5), ws.next()).await
        {
            let Some(text) = message.as_text() else {
                continue;
            };
            let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
                continue;
            };
            if value["id"] != 1 {
                continue;
            }
            if value.get("error").is_some() {
                // Storage.getCookies is not available on very old builds.
                method = "Network.getAllCookies";
                switch_method = true;
                break;
            }
            for cookie in value["result"]["cookies"].as_array().into_iter().flatten() {
                let domain = cookie["domain"].as_str().unwrap_or_default();
                if !domain.contains("aliyun.com") {
                    continue;
                }
                if let (Some(name), Some(value)) =
                    (cookie["name"].as_str(), cookie["value"].as_str())
                {
                    jar.cookies.insert(name.to_owned(), value.to_owned());
                }
            }
            break;
        }

        if switch_method {
            continue;
        }
        if !jar.cookies.is_empty() {
            break;
        }
    }

    let _ = child.kill();

    if jar.cookies.is_empty() {
        return Err(websocket_error(
            "login completed but no aliyun cookie could be read from the browser".to_owned(),
        ));
    }

    jar.save_to_file(cookie_file)
        .map_err(|e| websocket_error(format!("cannot save cookies: {e}")))?;
    tracing::info!(
        "Collected {} aliyun cookie(s) into {}",
        jar.cookies.len(),
        cookie_file.display()
    );
    Ok(jar)
}

/// Confirm that the gateway accepts the harvested session by doing a throw-away
/// WebSocket handshake with the cookies attached. Success means the next
/// reconnect attempt will complete; a redirect back to the login page means the
/// cookies were rejected and the user has to supply them manually.
async fn verify_harvested_cookies(entry_url: &url::Url, jar: &CookieJar) {
    let result = async {
        let mut connect_url = entry_url.clone();
        // socket_addrs has no known default port for wss, fill it in explicitly.
        if connect_url.port().is_none() {
            let port = if is_wss(entry_url)? { 443 } else { 80 };
            let _ = connect_url.set_port(Some(port));
        }
        let addr = SocketAddr::from_url(connect_url, IpVersion::Both).await?;
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        let tcp_stream = socket.connect(addr).await?;
        let rt_socket = RuntimeTcpSocket::new(tcp_stream);

        let stream: MaybeTlsStream<RuntimeTcpSocket> = if is_wss(entry_url)? {
            let tls = tokio_rustls::TlsConnector::from(Arc::new(get_insecure_tls_client_config()));
            let sni = entry_url.domain().unwrap_or("localhost").to_owned();
            let server_name = rustls::pki_types::ServerName::try_from(sni)
                .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
            MaybeTlsStream::Rustls(tls.connect(server_name, rt_socket).await?)
        } else {
            MaybeTlsStream::Plain(rt_socket)
        };

        let builder = ClientBuilder::from_uri(http::Uri::try_from(entry_url.to_string()).unwrap())
            .max_headers(128);
        match manual_ws_upgrade(&builder, stream, entry_url, jar).await? {
            UpgradeOutcome::Success(_) => Ok::<(), TunnelError>(()),
            UpgradeOutcome::Redirect { location, .. } => Err(websocket_error(format!(
                "gateway still redirects to {location}"
            ))),
        }
    }
    .await;

    match result {
        Ok(()) => tracing::info!(
            "aliyun cookies accepted by the gateway; the next reconnect attempt will connect"
        ),
        Err(e) => tracing::warn!(
            "aliyun cookies were harvested but the gateway did not accept them ({e}); \
             export the browser cookies manually and point EASYTIER_COOKIE_FILE at them"
        ),
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

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
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

            // Guard: the very first line MUST start with "HTTP/" or the server
            // isn't speaking HTTP at all (e.g. a proxy injecting SOCKS5/STUN/llhttp).
            let first_line = lines.next().unwrap_or_default();
            if first_line.len() < 5 || &first_line[..5] != b"HTTP/" {
                let dump = String::from_utf8_lossy(&buf[..total_read.min(256)])
                    .replace('\r', "\\r")
                    .replace('\n', "\\n");
                return Err(websocket_error(format!(
                    "server did not speak HTTP during WebSocket handshake: \
                     expected 'HTTP/' status line, got first bytes: {dump}"
                )));
            }

            let status_code = {
                let mut parts = first_line.split(|&b| b == b' ');
                parts.next(); // skip "HTTP/1.1"
                parts
                    .next()
                    .and_then(|code| {
                        std::str::from_utf8(code)
                            .ok()
                            .and_then(|s| s.trim().parse::<u16>().ok())
                    })
                    .unwrap_or(0)
            };

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

        if is_aliyun_login_url(&location) {
            tracing::info!(
                "WebSocket upgrade redirected to aliyun login ({status_code}): {location}, recording {} cookie(s)",
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
        if addr.host_str().is_some_and(|h| h.contains("login")) {
            return Err(websocket_error(format!(
                "server returned status {status_code} for login endpoint {addr}: \
                 authentication required. Export the login cookies to a file and set \
                 EASYTIER_COOKIE_FILE to it."
            )));
        }
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

    let saved_cookie_file = cookie_file_path();
    let mut cookie_jar = if saved_cookie_file.exists() {
        match CookieJar::load_from_file(&saved_cookie_file.to_string_lossy()) {
            Ok(jar) => {
                tracing::info!(
                    "Loaded {} cookie(s) from {}",
                    jar.cookies.len(),
                    saved_cookie_file.display()
                );
                jar
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to load cookies from {}: {e}",
                    saved_cookie_file.display()
                );
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
    let mut login_attempted = false;
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

                // Not signed in yet: pop up a browser window once per process and
                // let it run in the background, so the outer reconnect timeout
                // cannot cancel the login. The manual connector retries every
                // second, so as soon as the cookie file appears the next attempt
                // picks it up and connects.
                if is_aliyun_login_url(&location)
                    && !cookie_jar.has_login_session()
                    && !login_attempted
                {
                    login_attempted = true;
                    let cookie_file = cookie_file_path();

                    if LOGIN_IN_PROGRESS.load(Ordering::Relaxed) {
                        tracing::debug!(
                            "aliyun login is already running in the background; \
                             waiting for it to finish"
                        );
                        return Err(websocket_error(
                            "aliyun login is running in the browser, waiting for it to finish"
                                .to_owned(),
                        ));
                    }

                    if login_recently_attempted(&cookie_file) {
                        tracing::debug!(
                            "aliyun login was attempted within the last {}s; \
                             not opening another browser window",
                            LOGIN_RETRY_COOLDOWN.as_secs()
                        );
                        return Err(websocket_error(format!(
                            "redirected to aliyun login at {location}, but a browser \
                             login already ran recently and did not produce a working \
                             session — export the cookies manually and point \
                             EASYTIER_COOKIE_FILE at them, or remove {} to retry",
                            login_marker_path(&cookie_file).display()
                        )));
                    }

                    LOGIN_IN_PROGRESS.store(true, Ordering::Relaxed);
                    mark_login_attempted(&cookie_file);
                    tracing::warn!(
                        "Opening a browser window for the aliyun login in the \
                         background; the cookie file will be written to {} once \
                         you finish signing in. Further reconnect attempts keep \
                         running, so the tunnel comes up right after the login.",
                        cookie_file.display()
                    );

                    tokio::spawn(async move {
                        let _guard = LoginInProgressGuard;
                        // Hand the *original* wss endpoint to interactive_login
                        // and let it open the https:// counterpart — that way
                        // the browser follows the full 302 chain through the
                        // OAuth callback, which is where the gateway actually
                        // writes its session cookie.
                        match interactive_login(&remote_url, &cookie_file).await {
                            Ok(jar) => verify_harvested_cookies(&remote_url, &jar).await,
                            Err(e) => tracing::warn!("aliyun browser login failed: {e}"),
                        }
                    });

                    return Err(websocket_error(format!(
                        "redirected to aliyun login, browser popup scheduled for \
                         {location} — the tunnel will connect as soon as you sign in"
                    )));
                }

                current_url = resolve_redirect(&current_url, &location)?;
                let new_is_wss = is_wss(&current_url)?;
                // easytier's socket_addrs only accepts an explicit port or an easytier
                // scheme; http/https have no easytier default port, so fill it in here.
                let mut resolve_url = current_url.clone();
                if resolve_url.port().is_none() {
                    let _ = resolve_url.set_port(Some(if new_is_wss { 443 } else { 80 }));
                }
                let addr = SocketAddr::from_url(resolve_url, IpVersion::Both).await?;
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
