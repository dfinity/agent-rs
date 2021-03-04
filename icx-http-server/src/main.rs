use clap::{crate_authors, crate_version, AppSettings, Clap};
use hyper::http::uri::Parts;
use hyper::service::{make_service_fn, service_fn};
use hyper::{body, Body, Client, Request, Response, Server, StatusCode, Uri};
use ic_agent::export::Principal;
use ic_agent::Agent;
use ic_utils::call::SyncCall;
use ic_utils::interfaces::http_request::HeaderField;
use ic_utils::interfaces::HttpRequestCanister;
use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clap)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    global_setting = AppSettings::GlobalVersion,
    global_setting = AppSettings::ColoredHelp
)]
struct Opts {
    /// The address to bind to.
    #[clap(long, default_value = "127.0.0.1:3000")]
    address: SocketAddr,

    /// Some input. Because this isn't an Option<T> it's required to be used
    #[clap(long, default_value = "http://localhost:8000/")]
    replica: Vec<String>,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,
}

fn resolve_canister_id_from_hostname(hostname: &str) -> Option<Principal> {
    let url = Uri::from_str(hostname).ok()?;

    // Check if it's localhost or ic0.
    match url.host()?.split('.').collect::<Vec<&str>>().as_slice() {
        [.., maybe_canister_id, "localhost"] | [.., maybe_canister_id, "ic0", "app"] => {
            match Principal::from_text(maybe_canister_id) {
                Ok(canister_id) => return Some(canister_id),
                _ => {}
            }
        }
        _ => {}
    };

    None
}

fn resolve_canister_id_from_query(url: &hyper::Uri) -> Option<Principal> {
    let (_, canister_id) = url::form_urlencoded::parse(url.query()?.as_bytes())
        .find(|(name, _)| name == "canisterId")?;
    Principal::from_text(canister_id.as_ref()).ok()
}

fn resolve_canister_id(request: &Request<Body>) -> Option<Principal> {
    // Look for subdomains if there's a host header.
    if let Some(host_header) = request.headers().get("Host") {
        if let Ok(host) = host_header.to_str() {
            if let Some(canister_id) = resolve_canister_id_from_hostname(host) {
                return Some(canister_id);
            }
        }
    }

    // Look into the URI.
    if let Some(canister_id) = resolve_canister_id_from_query(request.uri()) {
        return Some(canister_id);
    }

    // Look into the request by header.
    if let Some(referer_header) = request.headers().get("referer") {
        if let Ok(referer) = referer_header.to_str() {
            if let Ok(referer_uri) = hyper::Uri::from_str(referer) {
                if let Some(canister_id) = resolve_canister_id_from_query(&referer_uri) {
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
) -> Result<Response<Body>, Box<dyn Error>> {
    let canister_id = match resolve_canister_id(&request) {
        None => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Could not find a canister id to forward to.".into())
                .unwrap())
        }
        Some(x) => x,
    };

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
        .collect();

    let entire_body = body::to_bytes(request.into_body()).await?.to_vec();

    HttpRequestCanister::create(agent.as_ref(), canister_id)
        .http_request(method, uri.to_string(), headers, &entire_body)
        .call()
        .await
        .map_err(Into::<Box<dyn Error>>::into)
        .and_then(|(http_response,)| {
            let mut builder =
                Response::builder().status(StatusCode::from_u16(http_response.status_code)?);
            for HeaderField(name, value) in http_response.headers {
                builder = builder.header(&name, value);
            }
            Ok(builder.body(http_response.body.into())?)
        })
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

    let client = Client::new();
    let response = client.request(proxied_request).await?;
    Ok(response)
}

async fn handle_request(
    ip_addr: IpAddr,
    request: Request<Body>,
    replica_url: String,
    debug: bool,
) -> Result<Response<Body>, Infallible> {
    match if request.uri().path().starts_with("/api/") {
        forward_api(&ip_addr, request, &replica_url).await
    } else {
        let agent = Arc::new(
            ic_agent::Agent::builder()
                .with_url(replica_url)
                .build()
                .expect("Could not create agent..."),
        );

        forward_request(request, agent).await
    } {
        Err(err) => Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(if debug {
                format!("Internal Error: {:?}", err).into()
            } else {
                "Internal Server Error".into()
            })
            .unwrap()),
        Ok(x) => Ok::<_, Infallible>(x),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts: Opts = Opts::parse();

    // Prepare a list of agents for each backend replicas.
    let replicas = Mutex::new(opts.replica.clone());

    let counter = AtomicUsize::new(0);
    let debug = opts.debug;

    let service = make_service_fn(|socket: &hyper::server::conn::AddrStream| {
        let ip_addr = socket.remote_addr();
        let ip_addr = ip_addr.ip().clone();

        // Select an agent.
        let replica_url_array = replicas.lock().unwrap();
        let count = counter.fetch_add(1, Ordering::SeqCst);
        let replica_url = replica_url_array
            .get(count % replica_url_array.len())
            .unwrap_or_else(|| unreachable!());
        let replica_url = replica_url.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(ip_addr, req, replica_url.clone(), debug)
            }))
        }
    });

    eprintln!("Starting server. Listening on http://{}/", opts.address);

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let server = Server::bind(&opts.address).serve(service);
        server.await?;
        Ok(())
    })
}
