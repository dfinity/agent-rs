use candid::{
    check_prog,
    parser::value::IDLValue,
    types::{Function, Type},
    CandidType, Decode, Deserialize, IDLArgs, IDLProg, TypeEnv,
};
use clap::{crate_authors, crate_version, AppSettings, Clap};
use ic_agent::{
    agent,
    agent::{
        agent_error::HttpErrorPayload, http_transport::ReqwestHttpReplicaV2Transport,
        ReplicaV2Transport,
    },
    export::Principal,
    identity::BasicIdentity,
    Agent, AgentError, Identity, RequestId,
};
use ic_utils::interfaces::management_canister::{
    builders::{CanisterInstall, CanisterSettings},
    MgmtMethod,
};
use ring::signature::Ed25519KeyPair;
use std::{
    collections::VecDeque, convert::TryFrom, future::Future, io::BufRead, path::PathBuf, pin::Pin,
    str::FromStr,
};
use thiserror::Error;

#[derive(Clap)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    global_setting = AppSettings::GlobalVersion,
    global_setting = AppSettings::ColoredHelp
)]
struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[clap(default_value = "http://localhost:8000/")]
    replica: String,

    /// Set for non-IC networks: fetch the root key.  If not passed, use real hardcoded key.
    #[clap(long)]
    fetch_root_key: bool,

    /// An optional PEM file to read the identity from. If none is passed,
    /// a random identity will be created.
    #[clap(long)]
    pem: Option<PathBuf>,

    /// An optional field to set the expiry time on requests. Can be a human
    /// readable time (like `100s`) or a number of seconds.
    #[clap(long)]
    ttl: Option<humantime::Duration>,

    #[clap(subcommand)]
    subcommand: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    /// Sends an update call to the replica.
    Update(CallOpts),

    /// Send a query call to the replica.
    Query(CallOpts),

    /// Checks the `status` endpoints of the replica.
    Status,

    /// Send a serialized request, taking from STDIN.
    Send,

    /// Transform Principal from hex to new text.
    PrincipalConvert(PrincipalConvertOpts),
}

/// A subcommand for controlling testing
#[derive(Clap)]
struct CallOpts {
    /// The Canister ID to call.
    #[clap(parse(try_from_str), required = true)]
    canister_id: Principal,

    /// Output the serialization of a message to STDOUT.
    #[clap(long)]
    serialize: bool,

    /// Path to a candid file to analyze the argument. Otherwise candid will parse the
    /// argument without type hint.
    #[clap(long)]
    candid: Option<PathBuf>,

    #[clap(required = true)]
    method_name: String,

    /// The type of output (hex or IDL).
    #[clap(long, default_value = "idl")]
    arg: ArgType,

    /// The type of output (hex or IDL).
    #[clap(long, default_value = "idl")]
    output: ArgType,

    /// Argument to send, in Candid textual format.
    #[clap()]
    arg_value: Option<String>,
}

#[derive(Clap)]
enum ArgType {
    Idl,
    Raw,
}

impl std::str::FromStr for ArgType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "idl" => Ok(ArgType::Idl),
            "raw" => Ok(ArgType::Raw),
            other => Err(format!("invalid argument type: {}", other)),
        }
    }
}

#[derive(Clap)]
struct PrincipalConvertOpts {
    /// Convert from hexadecimal to the new group-based Principal text.
    #[clap(long)]
    from_hex: Option<String>,
    /// Convert from the new group-based Principal text to hexadecimal.
    #[clap(long)]
    to_hex: Option<String>,
}

/// Parse IDL file into TypeEnv. This is a best effort function: it will succeed if
/// the IDL file can be parsed and type checked in Rust parser, and has an
/// actor in the IDL file. If anything fails, it returns None.
pub fn get_candid_type(
    idl_path: &std::path::Path,
    method_name: &str,
) -> Option<(TypeEnv, Function)> {
    let (env, ty) = check_candid_file(idl_path).ok()?;
    let actor = ty?;
    let method = env.get_method(&actor, method_name).ok()?.clone();
    Some((env, method))
}

pub fn check_candid_file(idl_path: &std::path::Path) -> Result<(TypeEnv, Option<Type>), String> {
    let idl_file = std::fs::read_to_string(idl_path).map_err(|e| format!("{:?}", e))?;
    let ast = idl_file
        .parse::<IDLProg>()
        .map_err(|e| format!("{:?}", e))?;
    let mut env = TypeEnv::new();
    let actor = check_prog(&mut env, &ast).map_err(|e| format!("{:?}", e))?;
    Ok((env, actor))
}

fn blob_from_arguments(
    mut arguments: Option<&str>,
    arg_type: &ArgType,
    method_type: &Option<(candid::parser::typing::TypeEnv, candid::types::Function)>,
) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    let args = if arguments == Some("-") {
        use std::io::Read;
        std::io::stdin().read_to_end(&mut buffer).unwrap();
        std::str::from_utf8(&buffer).ok()
    } else {
        arguments
    };
    match arg_type {
        ArgType::Raw => {
            let bytes = hex::decode(&args.unwrap_or(""))
                .map_err(|e| format!("Argument is not a valid hex string: {}", e))?;
            Ok(bytes)
        }
        ArgType::Idl => {
            let arguments = args.unwrap_or("()");
            let args: Result<IDLArgs, String> = arguments
                .parse::<IDLArgs>()
                .map_err(|e: candid::Error| format!("Invalid Candid values: {}", e));
            let typed_args = match method_type {
                None => args?.to_bytes(),
                Some((env, func)) => {
                    let first_char = arguments.chars().next();
                    let is_candid_format = first_char.map_or(false, |c| c == '(');
                    // If parsing fails and method expects a single value, try parsing as IDLValue.
                    // If it still fails, and method expects a text type, send arguments as text.
                    let args = args.or_else(|e| {
                        if func.args.len() == 1 && !is_candid_format {
                            let is_quote = first_char.map_or(false, |c| c == '"');
                            if candid::types::Type::Text == func.args[0] && !is_quote {
                                Ok(IDLValue::Text(arguments.to_string()))
                            } else {
                                arguments
                                    .parse::<IDLValue>()
                                    .map_err(|e| format!("Invalid Candid values: {}", e))
                            }
                            .map(|v| IDLArgs::new(&[v]))
                        } else {
                            Err(e)
                        }
                    });
                    args?.to_bytes_with_types(&env, &func.args)
                }
            }
            .map_err(|e| format!("Unable to serialize Candid values: {}", e))?;
            Ok(typed_args)
        }
    }
}

fn print_idl_blob(
    blob: &[u8],
    output_type: &ArgType,
    method_type: &Option<(TypeEnv, Function)>,
) -> Result<(), String> {
    match output_type {
        ArgType::Raw => {
            let hex_string = hex::encode(blob);
            println!("{}", hex_string);
        }
        ArgType::Idl => {
            let result = match method_type {
                None => candid::IDLArgs::from_bytes(blob),
                Some((env, func)) => candid::IDLArgs::from_bytes_with_types(blob, &env, &func.rets),
            };
            if result.is_err() {
                let hex_string = hex::encode(blob);
                eprintln!("Error deserializing blob 0x{}", hex_string);
            }
            println!("{}", result.map_err(|e| format!("{:?}", e))?);
        }
    }
    Ok(())
}

pub fn get_effective_canister_id(
    is_management_canister: bool,
    method_name: &str,
    arg_value: &[u8],
    canister_id: Principal,
) -> Result<Principal, String> {
    if is_management_canister {
        let method_name = MgmtMethod::from_str(method_name).map_err(|_| {
            format!(
                "Attempted to call an unsupported management canister method: {}",
                method_name
            )
        })?;
        match method_name {
            MgmtMethod::CreateCanister | MgmtMethod::RawRand => Err(format!(
                "{} can only be called via an inter-canister call.",
                method_name.as_ref()
            )),
            MgmtMethod::InstallCode => {
                let install_args = candid::Decode!(arg_value, CanisterInstall)
                    .map_err(|err| format!("Candid decode err: {}", err))?;
                Ok(install_args.canister_id)
            }
            MgmtMethod::StartCanister
            | MgmtMethod::StopCanister
            | MgmtMethod::CanisterStatus
            | MgmtMethod::DeleteCanister
            | MgmtMethod::DepositCycles
            | MgmtMethod::UninstallCode
            | MgmtMethod::ProvisionalTopUpCanister => {
                #[derive(CandidType, Deserialize)]
                struct In {
                    canister_id: Principal,
                }
                let in_args = candid::Decode!(arg_value, In)
                    .map_err(|err| format!("Candid decode err: {}", err))?;
                Ok(in_args.canister_id)
            }
            MgmtMethod::ProvisionalCreateCanisterWithCycles => Ok(Principal::management_canister()),
            MgmtMethod::UpdateSettings => {
                #[derive(CandidType, Deserialize)]
                struct In {
                    canister_id: Principal,
                    settings: CanisterSettings,
                }
                let in_args = candid::Decode!(arg_value, In)
                    .map_err(|err| format!("Candid decode err: {}", err))?;
                Ok(in_args.canister_id)
            }
        }
    } else {
        Ok(canister_id)
    }
}

fn create_identity(maybe_pem: Option<PathBuf>) -> impl Identity {
    if let Some(pem_path) = maybe_pem {
        BasicIdentity::from_pem_file(pem_path).expect("Could not read the key pair.")
    } else {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("Could not generate a key pair.")
            .as_ref()
            .to_vec();

        BasicIdentity::from_key_pair(
            Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Could not generate the key pair."),
        )
    }
}

#[derive(Error, Debug)]
enum SerializeError {
    #[error("")]
    Success,
}

struct SerializingTransport;

impl agent::ReplicaV2Transport for SerializingTransport {
    fn query<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(
            _: &SerializingTransport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Result<Vec<u8>, AgentError> {
            print!(
                "query\n\n{}\n\n{}",
                hex::encode(envelope),
                hex::encode(effective_canister_id)
            );
            Err(AgentError::TransportError(SerializeError::Success.into()))
        }

        Box::pin(run(self, effective_canister_id, envelope))
    }

    fn read_state<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(
            _: &SerializingTransport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
        ) -> Result<Vec<u8>, AgentError> {
            print!(
                "read_state\n\n{}\n\n{}",
                hex::encode(envelope),
                hex::encode(effective_canister_id)
            );
            Err(AgentError::TransportError(SerializeError::Success.into()))
        }

        Box::pin(run(self, effective_canister_id, envelope))
    }

    fn call<'a>(
        &'a self,
        effective_canister_id: Principal,
        envelope: Vec<u8>,
        request_id: RequestId,
    ) -> Pin<Box<dyn Future<Output = Result<(), AgentError>> + Send + 'a>> {
        async fn run(
            _: &SerializingTransport,
            effective_canister_id: Principal,
            envelope: Vec<u8>,
            request_id: RequestId,
        ) -> Result<(), AgentError> {
            print!(
                "call\n{}\n\n{}\n\n{}",
                hex::encode(request_id.as_slice()),
                hex::encode(envelope),
                hex::encode(effective_canister_id)
            );
            Err(AgentError::MessageError(String::new()))
        }

        Box::pin(run(self, effective_canister_id, envelope, request_id))
    }

    fn status<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AgentError>> + Send + 'a>> {
        async fn run(_: &SerializingTransport) -> Result<Vec<u8>, AgentError> {
            Err(AgentError::MessageError(
                "status calls not supported".to_string(),
            ))
        }

        Box::pin(run(self))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts: Opts = Opts::parse();

    let agent = match &opts.subcommand {
        SubCommand::Query(CallOpts {
            serialize: true, ..
        })
        | SubCommand::Update(CallOpts {
            serialize: true, ..
        }) => Agent::builder().with_transport(SerializingTransport),
        _ => Agent::builder().with_transport(
            agent::http_transport::ReqwestHttpReplicaV2Transport::create(opts.replica.clone())?,
        ),
    }
    .with_boxed_identity(Box::new(create_identity(opts.pem)))
    .build()?;

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match &opts.subcommand {
        SubCommand::Update(t) | SubCommand::Query(t) => {
            let maybe_candid_path = t.candid.as_ref();
            let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

            let method_type =
                maybe_candid_path.and_then(|path| get_candid_type(&path, &t.method_name));

            let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)?;
            let is_management_canister = t.canister_id == Principal::management_canister();
            let effective_canister_id = get_effective_canister_id(
                is_management_canister,
                &t.method_name,
                &arg,
                t.canister_id,
            )?;

            let result = match &opts.subcommand {
                SubCommand::Update(_) => {
                    // We need to fetch the root key for updates.
                    if opts.fetch_root_key {
                        agent.fetch_root_key().await?;
                    }

                    let mut builder = agent.update(&t.canister_id, &t.method_name);

                    if let Some(d) = expire_after {
                        builder.expire_after(d);
                    }

                    eprint!(".");
                    let result = builder
                        .with_arg(arg)
                        .with_effective_canister_id(effective_canister_id)
                        .call_and_wait(
                            garcon::Delay::builder()
                                .exponential_backoff(std::time::Duration::from_secs(1), 1.1)
                                .side_effect(|| {
                                    eprint!(".");
                                    Ok(())
                                })
                                .timeout(std::time::Duration::from_secs(60 * 5))
                                .build(),
                        )
                        .await;
                    eprintln!();
                    result
                }
                SubCommand::Query(_) => {
                    let mut builder = agent.query(&t.canister_id, &t.method_name);
                    if let Some(d) = expire_after {
                        builder.expire_after(d);
                    }

                    builder
                        .with_arg(&arg)
                        .with_effective_canister_id(effective_canister_id)
                        .call()
                        .await
                }
                _ => unreachable!(),
            };

            match result {
                Ok(blob) => {
                    print_idl_blob(&blob, &t.output, &method_type)
                        .map_err(|e| format!("Invalid IDL blob: {}", e))?;
                }
                Err(AgentError::TransportError(_)) => return Ok(()),
                Err(AgentError::HttpError(HttpErrorPayload {
                    status,
                    content_type,
                    content,
                })) => {
                    eprintln!("Server returned an HTTP Error:\n  Code: {}", status);
                    match content_type.as_deref() {
                        None => eprintln!("  Content: {}", hex::encode(content)),
                        Some("text/plain; charset=UTF-8") | Some("text/plain") => {
                            eprintln!("  ContentType: text/plain");
                            eprintln!("  Content:     {}", String::from_utf8_lossy(&content));
                        }
                        Some(x) => {
                            eprintln!("  ContentType: {}", x);
                            eprintln!("  Content:     {}", hex::encode(&content));
                        }
                    }
                }
                Err(s) => eprintln!("Error: {:?}", s),
            }
        }
        SubCommand::Status => println!("{:#}", agent.status().await?),
        SubCommand::PrincipalConvert(t) => {
            if let Some(hex) = &t.from_hex {
                let p = Principal::try_from(hex::decode(hex).expect("Could not decode hex: {}"))
                    .expect("Could not transform into a Principal: {}");
                eprintln!("Principal: {}", p);
            } else if let Some(txt) = &t.to_hex {
                let p = Principal::from_text(txt.as_str())
                    .expect("Could not transform into a Principal: {}");
                eprintln!("Hexadecimal: {}", hex::encode(p.as_slice()));
            }
        }
        SubCommand::Send => {
            let mut input: VecDeque<String> = std::io::stdin()
                .lock()
                .lines()
                .collect::<Result<VecDeque<String>, std::io::Error>>()?;
            let mut line = input.pop_front().unwrap();
            while line == "" {
                line = input.pop_front().unwrap();
            }

            let transport = ReqwestHttpReplicaV2Transport::create(opts.replica)?;
            match line.as_str() {
                "call" => {
                    line = input.pop_front().unwrap(); // request id.
                    let request_id = RequestId::from_str(&line)?;
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // envelope
                    let envelope = hex::decode(line)?;
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // effective_canister_id
                    let effective_canister_id = Principal::try_from(hex::decode(line)?)?;
                    transport
                        .call(effective_canister_id, envelope, request_id)
                        .await?;
                    eprint!("Request ID: ");
                    println!("0x{}", hex::encode(request_id.as_slice()));
                }
                "read_state" => {
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // envelope
                    let envelope = hex::decode(line)?;
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // effective_canister_id
                    let effective_canister_id = Principal::try_from(hex::decode(line)?)?;
                    let result = transport
                        .read_state(effective_canister_id, envelope)
                        .await?;
                    eprint!("Result: ");
                    println!("{}", hex::encode(result));
                }
                "query" => {
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // envelope
                    let envelope = hex::decode(line)?;
                    input.pop_front().unwrap(); // empty line.
                    line = input.pop_front().unwrap(); // effective_canister_id
                    let effective_canister_id = Principal::try_from(hex::decode(line)?)?;
                    let result = transport.query(effective_canister_id, envelope).await?;
                    eprint!("Result: ");
                    println!("{}", hex::encode(result));
                }
                other => {
                    eprintln!(
                        r#"Error: Invalid STDIN format. Unexpected line: "{}""#,
                        other
                    );
                }
            }
        }
    }

    Ok(())
}
