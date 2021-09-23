use crate::config::dns_canister_config::DnsCanisterConfig;
use clap::{crate_authors, crate_version, AppSettings, Clap};
use hyper::{
    body,
    body::Bytes,
    http::uri::Parts,
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server, StatusCode, Uri,
};
use ic_agent::{
    agent::http_transport::ReqwestHttpReplicaV2Transport, export::Principal, Agent, AgentError,
};
use ic_utils::{
    call::AsyncCall,
    call::SyncCall,
    interfaces::http_request::{
        HeaderField, HttpRequestCanister, HttpResponse, StreamingCallbackHttpResponse, StreamingStrategy,
    },
};
use slog::Drain;
use std::{
    convert::Infallible,
    error::Error,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

mod config;
mod logging;

// Limit the total number of calls to an HTTP Request loop to 1000 for now.
static MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT: i32 = 1000;

// The maximum length of a body we should log as tracing.
static MAX_LOG_BODY_SIZE: usize = 100;

#[derive(Clap)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    global_setting = AppSettings::GlobalVersion,
    global_setting = AppSettings::ColoredHelp
)]
pub(crate) struct Opts {
    /// Verbose level. By default, INFO will be used. Add a single `-v` to upgrade to
    /// DEBUG, and another `-v` to upgrade to TRACE.
    #[clap(long, short('v'), parse(from_occurrences))]
    verbose: u64,

    /// Quiet level. The opposite of verbose. A single `-q` will drop the logging to
    /// WARN only, then another one to ERR, and finally another one for FATAL. Another
    /// `-q` will silence ALL logs.
    #[clap(long, short('q'), parse(from_occurrences))]
    quiet: u64,

    /// Mode to use the logging. "stderr" will output logs in STDERR, "file" will output
    /// logs in a file, and "tee" will do both.
    #[clap(long("log"), default_value("stderr"), possible_values(&["stderr", "tee", "file"]))]
    logmode: String,

    /// File to output the log to, when using logmode=tee or logmode=file.
    #[clap(long)]
    logfile: Option<PathBuf>,

    /// The address to bind to.
    #[clap(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    /// A replica to use as backend. Locally, this should be a local instance or the
    /// boundary node. Multiple replicas can be passed and they'll be used round-robin.
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: Vec<String>,

    /// An address to forward any requests from /_/
    #[clap(long)]
    proxy: Option<String>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,

    /// A map of domain names to canister IDs.
    /// Format: domain.name:canister-id
    #[clap(long)]
    dns_alias: Vec<String>,

    /// A list of domain name suffixes.  If found, the next (to the left) subdomain
    /// is used as the Principal, if it parses as a Principal.
    #[clap(long, default_value = "localhost")]
    dns_suffix: Vec<String>,

    /// Set for non-IC networks: fetch the root key.  If not passed, use real hardcoded key.
    #[clap(long)]
    fetch_root_key: bool,
}

fn resolve_canister_id_from_hostname(
    hostname: &str,
    dns_canister_config: &DnsCanisterConfig,
) -> Option<Principal> {
    let url = Uri::from_str(hostname).ok()?;

    let split_hostname = url.host()?.split('.').collect::<Vec<&str>>();
    let split_hostname = split_hostname.as_slice();

    if let Some(principal) =
        dns_canister_config.resolve_canister_id_from_split_hostname(split_hostname)
    {
        return Some(principal);
    }
    // Check if it's localhost or ic0.
    match split_hostname {
        [.., maybe_canister_id, "localhost"] => Principal::from_text(maybe_canister_id).ok(),
        [maybe_canister_id, ..] => Principal::from_text(maybe_canister_id).ok(),
        _ => None,
    }
}

fn resolve_canister_id_from_uri(url: &hyper::Uri) -> Option<Principal> {
    let (_, canister_id) = url::form_urlencoded::parse(url.query()?.as_bytes())
        .find(|(name, _)| name == "canisterId")?;
    Principal::from_text(canister_id.as_ref()).ok()
}

/// Try to resolve a canister ID from an HTTP Request. If it cannot be resolved,
/// [None] will be returned.
fn resolve_canister_id(
    request: &Request<Body>,
    dns_canister_config: &DnsCanisterConfig,
) -> Option<Principal> {
    // Look for subdomains if there's a host header.
    if let Some(host_header) = request.headers().get("Host") {
        if let Ok(host) = host_header.to_str() {
            if let Some(canister_id) = resolve_canister_id_from_hostname(host, dns_canister_config)
            {
                return Some(canister_id);
            }
        }
    }

    // Look into the URI.
    if let Some(canister_id) = resolve_canister_id_from_uri(request.uri()) {
        return Some(canister_id);
    }

    // Look into the request by header.
    if let Some(referer_header) = request.headers().get("referer") {
        if let Ok(referer) = referer_header.to_str() {
            if let Ok(referer_uri) = hyper::Uri::from_str(referer) {
                if let Some(canister_id) = resolve_canister_id_from_uri(&referer_uri) {
                    return Some(canister_id);
                }
            }
        }
    }

    None
}

async fn forward_request(
    request: Request<Body>,
    agent: Arc<Agent>,
    dns_canister_config: &DnsCanisterConfig,
    logger: slog::Logger,
) -> Result<Response<Body>, Box<dyn Error>> {
    let canister_id = match resolve_canister_id(&request, dns_canister_config) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Could not find a canister id to forward to.".into())
                .unwrap())
        }
        Some(x) => x,
    };

    slog::trace!(
        logger,
        "<< {} {} {:?}",
        request.method(),
        request.uri(),
        &request.version()
    );

    let method = request.method().to_string();
    let uri = request.uri().clone();
    let headers = request
        .headers()
        .into_iter()
        .filter_map(|(name, value)| {
            Some(HeaderField(
                name.to_string(),
                value.to_str().ok()?.to_string(),
            ))
        })
        .inspect(|HeaderField(name, value)| {
            slog::trace!(logger, "<< {}: {}", name, value);
        })
        .collect::<Vec<_>>();

    let entire_body = body::to_bytes(request.into_body()).await?.to_vec();

    slog::trace!(logger, "<<");
    if logger.is_trace_enabled() {
        let body = String::from_utf8_lossy(&entire_body);
        slog::trace!(
            logger,
            "<< {}{}",
            &body[0..usize::min(body.len(), MAX_LOG_BODY_SIZE)],
            if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    let canister = HttpRequestCanister::create(agent.as_ref(), canister_id);
    let query_result = canister
        .http_request(method.clone(), uri.to_string(), headers.clone(), &entire_body)
        .call()
        .await;

    fn handle_result(result: Result<(HttpResponse,), AgentError>) -> Result<HttpResponse, Result<Response<Body>, Box<dyn Error>>> {
        // If the result is a Replica error, returns the 500 code and message. There is no information
        // leak here because a user could use `dfx` to get the same reply.
        match result {
            Ok((http_response,)) => Ok(http_response),
            Err(AgentError::ReplicaError {
                reject_code,
                reject_message,
            }) => {
                Err(Ok(Response::builder()
                          .status(StatusCode::INTERNAL_SERVER_ERROR)
                          .body(format!(r#"Replica Error ({}): "{}""#, reject_code, reject_message).into())
                          .unwrap()))
            }
            Err(e) => Err(Err(e.into())),
        }
    }

    let http_response = match handle_result(query_result) {
        Ok(http_response) => http_response,
        Err(response_or_error) => return response_or_error,
    };

    let http_response = if http_response.upgrade {
        let waiter = garcon::Delay::builder()
            .throttle(std::time::Duration::from_millis(500))
            .timeout(std::time::Duration::from_secs(60 * 5))
            .build();
        let update_result = canister
            .http_request_update(method, uri.to_string(), headers, &entire_body)
            .call_and_wait(waiter)
            .await;
        let http_response = match handle_result(update_result) {
            Ok(http_response) => http_response,
            Err(response_or_error) => return response_or_error,
        };
        http_response
    } else {
        http_response
    };

    let mut builder = Response::builder().status(StatusCode::from_u16(http_response.status_code)?);
    for HeaderField(name, value) in http_response.headers {
        builder = builder.header(&name, value);
    }

    let body = if logger.is_trace_enabled() {
        Some(http_response.body.clone())
    } else {
        None
    };
    let is_streaming = http_response.streaming_strategy.is_some();
    let response = if let Some(streaming_strategy) = http_response.streaming_strategy {
        let (mut sender, body) = body::Body::channel();
        let agent = agent.as_ref().clone();
        sender.send_data(Bytes::from(http_response.body)).await?;

        match streaming_strategy {
            StreamingStrategy::Callback(callback) => {
                let streaming_canister_id_id = callback.callback.principal;
                let method_name = callback.callback.method;
                let mut callback_token = callback.token;
                let logger = logger.clone();
                tokio::spawn(async move {
                    let canister = HttpRequestCanister::create(&agent, streaming_canister_id_id);
                    // We have not yet called http_request_stream_callback.
                    let mut count = 0;
                    loop {
                        count += 1;
                        if count > MAX_HTTP_REQUEST_STREAM_CALLBACK_CALL_COUNT {
                            sender.abort();
                            break;
                        }

                        match canister
                            .http_request_stream_callback(&method_name, callback_token)
                            .call()
                            .await
                        {
                            Ok((StreamingCallbackHttpResponse { body, token },)) => {
                                if sender.send_data(Bytes::from(body)).await.is_err() {
                                    sender.abort();
                                    break;
                                }
                                if let Some(next_token) = token {
                                    callback_token = next_token;
                                } else {
                                    break;
                                }
                            }
                            Err(e) => {
                                slog::debug!(logger, "Error happened during streaming: {}", e);
                                sender.abort();
                                break;
                            }
                        }
                    }
                });
            }
        }

        builder.body(body)?
    } else {
        builder.body(http_response.body.into())?
    };

    if logger.is_trace_enabled() {
        slog::trace!(
            logger,
            ">> {:?} {} {}",
            &response.version(),
            response.status().as_u16(),
            response.status().to_string()
        );

        for (name, value) in response.headers() {
            let value = String::from_utf8_lossy(value.as_bytes());
            slog::trace!(logger, ">> {}: {}", name, value);
        }

        let body = body.unwrap_or_else(|| b"... streaming ...".to_vec());

        slog::trace!(logger, ">>");
        slog::trace!(
            logger,
            ">> {}{}",
            match std::str::from_utf8(&body) {
                Ok(s) => format!(
                    r#""{}""#,
                    s[..usize::min(MAX_LOG_BODY_SIZE, s.len())].escape_default()
                ),
                Err(_) => hex::encode(&body[..usize::min(MAX_LOG_BODY_SIZE, body.len())]),
            },
            if is_streaming {
                "... streaming".to_string()
            } else if body.len() > MAX_LOG_BODY_SIZE {
                format!("... {} bytes total", body.len())
            } else {
                String::new()
            }
        );
    }

    Ok(response)
}

fn is_hop_header(name: &str) -> bool {
    name.to_ascii_lowercase() == "connection"
        || name.to_ascii_lowercase() == "keep-alive"
        || name.to_ascii_lowercase() == "proxy-authenticate"
        || name.to_ascii_lowercase() == "proxy-authorization"
        || name.to_ascii_lowercase() == "te"
        || name.to_ascii_lowercase() == "trailers"
        || name.to_ascii_lowercase() == "transfer-encoding"
        || name.to_ascii_lowercase() == "upgrade"
}

/// Returns a clone of the headers without the [hop-by-hop headers].
///
/// [hop-by-hop headers]: http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
fn remove_hop_headers(
    headers: &hyper::header::HeaderMap<hyper::header::HeaderValue>,
) -> hyper::header::HeaderMap<hyper::header::HeaderValue> {
    let mut result = hyper::HeaderMap::new();
    for (k, v) in headers.iter() {
        if !is_hop_header(k.as_str()) {
            result.insert(k.clone(), v.clone());
        }
    }
    result
}

fn forward_uri<B>(forward_url: &str, req: &Request<B>) -> Result<Uri, Box<dyn Error>> {
    let uri = Uri::from_str(forward_url)?;
    let mut parts = Parts::from(uri);
    parts.path_and_query = req.uri().path_and_query().cloned();

    Ok(Uri::from_parts(parts)?)
}

fn create_proxied_request<B>(
    client_ip: &IpAddr,
    forward_url: &str,
    mut request: Request<B>,
) -> Result<Request<B>, Box<dyn Error>> {
    *request.headers_mut() = remove_hop_headers(request.headers());
    *request.uri_mut() = forward_uri(forward_url, &request)?;

    let x_forwarded_for_header_name = "x-forwarded-for";

    // Add forwarding information in the headers
    match request.headers_mut().entry(x_forwarded_for_header_name) {
        hyper::header::Entry::Vacant(entry) => {
            entry.insert(client_ip.to_string().parse()?);
        }

        hyper::header::Entry::Occupied(mut entry) => {
            let addr = format!("{}, {}", entry.get().to_str()?, client_ip);
            entry.insert(addr.parse()?);
        }
    }

    Ok(request)
}

async fn forward_api(
    ip_addr: &IpAddr,
    request: Request<Body>,
    replica_url: &str,
) -> Result<Response<Body>, Box<dyn Error>> {
    let proxied_request = create_proxied_request(ip_addr, &replica_url, request)?;

    let client = Client::builder().build(hyper_tls::HttpsConnector::new());
    let response = client.request(proxied_request).await?;
    Ok(response)
}

fn not_found() -> Result<Response<Body>, Box<dyn Error>> {
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body("Not found".into())?)
}

async fn handle_request(
    ip_addr: IpAddr,
    request: Request<Body>,
    replica_url: String,
    proxy_url: Option<String>,
    dns_canister_config: Arc<DnsCanisterConfig>,
    logger: slog::Logger,
    debug: bool,
    fetch_root_key: bool,
) -> Result<Response<Body>, AgentError> {
    let request_uri_path = request.uri().path();
    match if request_uri_path.starts_with("/api/") {
        slog::debug!(
            logger,
            "URI Request to path '{}' being forwarded to Replica",
            &request.uri().path()
        );
        forward_api(&ip_addr, request, &replica_url).await
    } else if request_uri_path.starts_with("/_/") {
        if let Some(proxy_url) = proxy_url {
            slog::debug!(
                logger,
                "URI Request to path '{}' being forwarded to proxy",
                &request.uri().path(),
            );
            forward_api(&ip_addr, request, &proxy_url).await
        } else {
            slog::warn!(
                logger,
                "Unable to proxy {} because no --proxy is configured",
                &request.uri().path()
            );
            not_found()
        }
    } else {
        let agent = Arc::new(
            ic_agent::Agent::builder()
                .with_transport(ReqwestHttpReplicaV2Transport::create(replica_url).unwrap())
                .build()
                .expect("Could not create agent..."),
        );

        // We need to fetch the root key for updates.
        if fetch_root_key {
            agent.fetch_root_key().await?;
        }

        forward_request(request, agent, dns_canister_config.as_ref(), logger.clone()).await
    } {
        Err(err) => {
            slog::warn!(logger, "Internal Error during request:\n{:#?}", err);

            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(if debug {
                    format!("Internal Error: {:?}", err).into()
                } else {
                    "Internal Server Error".into()
                })
                .unwrap())
        }
        Ok(x) => Ok::<_, AgentError>(x),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    let logger = logging::setup_logging(&opts);

    // Prepare a list of agents for each backend replicas.
    let replicas = Mutex::new(opts.replica.clone());

    let dns_canister_config = Arc::new(DnsCanisterConfig::new(&opts.dns_alias, &opts.dns_suffix)?);

    let counter = AtomicUsize::new(0);
    let debug = opts.debug;
    let proxy_url = opts.proxy.clone();

    let service = make_service_fn(|socket: &hyper::server::conn::AddrStream| {
        let ip_addr = socket.remote_addr();
        let ip_addr = ip_addr.ip();
        let dns_canister_config = dns_canister_config.clone();
        let logger = logger.clone();
        let fetch_root_key = opts.fetch_root_key;

        // Select an agent.
        let replica_url_array = replicas.lock().unwrap();
        let count = counter.fetch_add(1, Ordering::SeqCst);
        let replica_url = replica_url_array
            .get(count % replica_url_array.len())
            .unwrap_or_else(|| unreachable!());
        let replica_url = replica_url.clone();
        slog::debug!(logger, "Replica URL: {}", replica_url);

        let proxy_url = proxy_url.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let logger = logger.clone();
                let dns_canister_config = dns_canister_config.clone();
                handle_request(
                    ip_addr,
                    req,
                    replica_url.clone(),
                    proxy_url.clone(),
                    dns_canister_config,
                    logger,
                    debug,
                    fetch_root_key,
                )
            }))
        }
    });

    slog::info!(
        logger,
        "Starting server. Listening on http://{}/",
        opts.address
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(10)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let server = Server::bind(&opts.address).serve(service);
        server.await?;
        Ok(())
    })
}
