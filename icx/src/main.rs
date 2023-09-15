use anyhow::{bail, Context, Result};
use candid::{
    check_prog,
    types::value::IDLValue,
    types::{Function, Type, TypeInner},
    CandidType, Decode, Deserialize, IDLArgs, IDLProg, TypeEnv,
};
use clap::{crate_authors, crate_version, Parser, ValueEnum};
use ic_agent::{
    agent::{self, signed::SignedUpdate},
    agent::{
        agent_error::HttpErrorPayload,
        signed::{SignedQuery, SignedRequestStatus},
    },
    export::Principal,
    identity::BasicIdentity,
    Agent, AgentError, Identity,
};
use ic_utils::interfaces::management_canister::{
    builders::{CanisterInstall, CanisterSettings},
    MgmtMethod,
};
use ring::signature::Ed25519KeyPair;
use std::{
    collections::VecDeque, convert::TryFrom, io::BufRead, path::PathBuf, str::FromStr,
    time::Duration,
};

const DEFAULT_IC_GATEWAY: &str = "https://ic0.app";

#[derive(Parser)]
#[clap(
    version = crate_version!(),
    author = crate_authors!(),
    propagate_version(true),
)]
struct Opts {
    /// Some input. Because this isn't an Option<T> it's required to be used
    #[clap(default_value = "http://localhost:8000/")]
    replica: String,

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

#[derive(Parser)]
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
#[derive(Parser)]
struct CallOpts {
    /// The Canister ID to call.
    canister_id: Principal,

    /// Output the serialization of a message to STDOUT.
    #[arg(long)]
    serialize: bool,

    /// Path to a candid file to analyze the argument. Otherwise candid will parse the
    /// argument without type hint.
    #[arg(long)]
    candid: Option<PathBuf>,

    method_name: String,

    /// The type of output (hex or IDL).
    #[arg(long, value_enum, default_value_t = ArgType::Idl)]
    arg: ArgType,

    /// The type of output (hex or IDL).
    #[arg(long, value_enum, default_value_t = ArgType::Idl)]
    output: ArgType,

    /// Argument to send, in Candid textual format.
    arg_value: Option<String>,
}

#[derive(ValueEnum, Clone)]
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

#[derive(Parser)]
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
) -> Result<Option<(TypeEnv, Function)>> {
    let (env, ty) = check_candid_file(idl_path).with_context(|| {
        format!(
            "Failed when checking candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    match ty {
        None => Ok(None),
        Some(actor) => {
            let method = env
                .get_method(&actor, method_name)
                .with_context(|| format!("Failed to get method: {}", method_name))?
                .clone();
            Ok(Some((env, method)))
        }
    }
}

pub fn check_candid_file(idl_path: &std::path::Path) -> Result<(TypeEnv, Option<Type>)> {
    let idl_file = std::fs::read_to_string(idl_path)
        .with_context(|| format!("Failed to read Candid file: {}", idl_path.to_string_lossy()))?;
    let ast = idl_file.parse::<IDLProg>().with_context(|| {
        format!(
            "Failed to parse the Candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    let mut env = TypeEnv::new();
    let actor = check_prog(&mut env, &ast).with_context(|| {
        format!(
            "Failed to type check the Candid file: {}",
            idl_path.to_string_lossy()
        )
    })?;
    Ok((env, actor))
}

fn blob_from_arguments(
    arguments: Option<&str>,
    arg_type: &ArgType,
    method_type: &Option<(TypeEnv, Function)>,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let arguments = if arguments == Some("-") {
        use std::io::Read;
        std::io::stdin().read_to_end(&mut buffer).unwrap();
        std::str::from_utf8(&buffer).ok()
    } else {
        arguments
    };

    match arg_type {
        ArgType::Raw => {
            let bytes = hex::decode(arguments.unwrap_or(""))
                .context("Argument is not a valid hex string")?;
            Ok(bytes)
        }
        ArgType::Idl => {
            let arguments = arguments.unwrap_or("()");
            let args = arguments.parse::<IDLArgs>();
            let typed_args = match method_type {
                None => args
                    .context("Failed to parse arguments with no method type info")?
                    .to_bytes(),
                Some((env, func)) => {
                    let first_char = arguments.chars().next();
                    let is_candid_format = first_char.map_or(false, |c| c == '(');
                    // If parsing fails and method expects a single value, try parsing as IDLValue.
                    // If it still fails, and method expects a text type, send arguments as text.
                    let args = args.or_else(|e| {
                        if func.args.len() == 1 && !is_candid_format {
                            let is_quote = first_char.map_or(false, |c| c == '"');
                            if &TypeInner::Text == func.args[0].as_ref() && !is_quote {
                                Ok(IDLValue::Text(arguments.to_string()))
                            } else {
                                arguments.parse::<IDLValue>()
                            }
                            .map(|v| IDLArgs::new(&[v]))
                        } else {
                            Err(e)
                        }
                    });
                    args.context("Failed to parse arguments with method type info")?
                        .to_bytes_with_types(env, &func.args)
                }
            }
            .context("Failed to serialize Candid values")?;
            Ok(typed_args)
        }
    }
}

fn print_idl_blob(
    blob: &[u8],
    output_type: &ArgType,
    method_type: &Option<(TypeEnv, Function)>,
) -> Result<()> {
    let hex_string = hex::encode(blob);
    match output_type {
        ArgType::Raw => {
            println!("{}", hex_string);
        }
        ArgType::Idl => {
            let result = match method_type {
                None => IDLArgs::from_bytes(blob),
                Some((env, func)) => IDLArgs::from_bytes_with_types(blob, env, &func.rets),
            };
            println!(
                "{}",
                result.with_context(|| format!("Failed to deserialize blob 0x{}", hex_string))?
            );
        }
    }
    Ok(())
}

async fn fetch_root_key_from_non_ic(agent: &Agent, replica: &str) -> Result<()> {
    let normalized_replica = replica.strip_suffix('/').unwrap_or(replica);
    if normalized_replica != DEFAULT_IC_GATEWAY {
        agent
            .fetch_root_key()
            .await
            .context("Failed to fetch root key from replica")?;
    }
    Ok(())
}
pub fn get_effective_canister_id(
    is_management_canister: bool,
    method_name: &str,
    arg_value: &[u8],
    canister_id: Principal,
) -> Result<Principal> {
    if is_management_canister {
        let method_name = MgmtMethod::from_str(method_name).with_context(|| {
            format!(
                "Attempted to call an unsupported management canister method: {}",
                method_name
            )
        })?;
        match method_name {
            MgmtMethod::CreateCanister | MgmtMethod::RawRand => bail!(
                "{} can only be called via an inter-canister call.",
                method_name.as_ref()
            ),
            MgmtMethod::InstallCode => {
                let install_args = Decode!(arg_value, CanisterInstall)
                    .context("Argument is not valid for CanisterInstall")?;
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
                let in_args =
                    Decode!(arg_value, In).context("Argument is not a valid Principal")?;
                Ok(in_args.canister_id)
            }
            MgmtMethod::ProvisionalCreateCanisterWithCycles => Ok(Principal::management_canister()),
            MgmtMethod::UpdateSettings => {
                #[derive(CandidType, Deserialize)]
                struct In {
                    canister_id: Principal,
                    settings: CanisterSettings,
                }
                let in_args =
                    Decode!(arg_value, In).context("Argument is not valid for UpdateSettings")?;
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

#[tokio::main]
async fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    let agent = Agent::builder()
        .with_transport(
            agent::http_transport::ReqwestTransport::create(opts.replica.clone())
                .context("Failed to create Transport for Agent")?,
        )
        .with_boxed_identity(Box::new(create_identity(opts.pem)))
        .build()
        .context("Failed to build the Agent")?;

    // You can handle information about subcommands by requesting their matches by name
    // (as below), requesting just the name used, or both at the same time
    match &opts.subcommand {
        SubCommand::Update(t) | SubCommand::Query(t) => {
            let maybe_candid_path = t.candid.as_ref();
            let expire_after: Option<std::time::Duration> = opts.ttl.map(|ht| ht.into());

            let method_type = match maybe_candid_path {
                None => None,
                Some(path) => get_candid_type(path, &t.method_name)
                    .context("Failed to get method type from candid file")?,
            };

            let arg = blob_from_arguments(t.arg_value.as_deref(), &t.arg, &method_type)
                .context("Invalid arguments")?;
            let is_management_canister = t.canister_id == Principal::management_canister();
            let effective_canister_id = get_effective_canister_id(
                is_management_canister,
                &t.method_name,
                &arg,
                t.canister_id,
            )
            .context("Failed to get effective_canister_id for this call")?;

            if !t.serialize {
                let result = match &opts.subcommand {
                    SubCommand::Update(_) => {
                        // We need to fetch the root key for updates.
                        fetch_root_key_from_non_ic(&agent, &opts.replica).await?;

                        let mut builder = agent.update(&t.canister_id, &t.method_name);

                        if let Some(d) = expire_after {
                            builder = builder.expire_after(d);
                        }

                        let printer = async {
                            loop {
                                eprint!(".");
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        };
                        let result = builder
                            .with_arg(arg)
                            .with_effective_canister_id(effective_canister_id)
                            .call_and_wait();
                        let result = tokio::select!(
                            Ok(unreachable) = tokio::spawn(printer) => unreachable,
                            res = tokio::time::timeout(Duration::from_secs(5 * 60), result) => res,
                        );
                        eprintln!();
                        result.unwrap_or(Err(AgentError::TimeoutWaitingForResponse()))
                    }
                    SubCommand::Query(_) => {
                        let mut builder = agent.query(&t.canister_id, &t.method_name);
                        if let Some(d) = expire_after {
                            builder = builder.expire_after(d);
                        }

                        builder
                            .with_arg(arg)
                            .with_effective_canister_id(effective_canister_id)
                            .call()
                            .await
                    }
                    _ => unreachable!(),
                };

                match result {
                    Ok(blob) => {
                        print_idl_blob(&blob, &t.output, &method_type)
                            .context("Failed to print result blob")?;
                    }
                    Err(AgentError::TransportError(_)) => return Ok(()),
                    Err(AgentError::HttpError(HttpErrorPayload {
                        status,
                        content_type,
                        content,
                    })) => {
                        let mut error_message =
                            format!("Server returned an HTTP Error:\n  Code: {}\n", status);
                        match content_type.as_deref() {
                            None => error_message
                                .push_str(&format!("  Content: {}\n", hex::encode(content))),
                            Some("text/plain; charset=UTF-8") | Some("text/plain") => {
                                error_message.push_str("  ContentType: text/plain\n");
                                error_message.push_str(&format!(
                                    "  Content:     {}\n",
                                    String::from_utf8_lossy(&content)
                                ));
                            }
                            Some(x) => {
                                error_message.push_str(&format!("  ContentType: {}\n", x));
                                error_message.push_str(&format!(
                                    "  Content:     {}\n",
                                    hex::encode(&content)
                                ));
                            }
                        }
                        bail!(error_message);
                    }
                    Err(s) => Err(s).context("Got an error when make the canister call")?,
                }
            } else {
                match &opts.subcommand {
                    SubCommand::Update(_) => {
                        // For local emulator, we need to fetch the root key for updates.
                        // So on an air-gapped machine, we can only generate message for the IC main net
                        // which agent hard-coded its root key
                        fetch_root_key_from_non_ic(&agent, &opts.replica).await?;

                        let mut builder = agent.update(&t.canister_id, &t.method_name);
                        if let Some(d) = expire_after {
                            builder = builder.expire_after(d);
                        }
                        let signed_update = builder
                            .with_arg(arg)
                            .with_effective_canister_id(effective_canister_id)
                            .sign()
                            .context("Failed to sign the update call")?;
                        let serialized = serde_json::to_string(&signed_update).unwrap();
                        println!("{}", serialized);

                        let signed_request_status = agent
                            .sign_request_status(effective_canister_id, signed_update.request_id)
                            .context(
                                "Failed to sign the request_status call accompany with the update",
                            )?;
                        let serialized = serde_json::to_string(&signed_request_status).unwrap();
                        println!("{}", serialized);
                    }
                    &SubCommand::Query(_) => {
                        let mut builder = agent.query(&t.canister_id, &t.method_name);
                        if let Some(d) = expire_after {
                            builder = builder.expire_after(d);
                        }
                        let signed_query = builder
                            .with_arg(arg)
                            .with_effective_canister_id(effective_canister_id)
                            .sign()
                            .context("Failed to sign the query call")?;
                        let serialized = serde_json::to_string(&signed_query).unwrap();
                        println!("{}", serialized);
                    }
                    _ => unreachable!(),
                }
            }
        }
        SubCommand::Status => {
            let status = agent
                .status()
                .await
                .context("Failed to get network status")?;
            println!("{:#}", status);
        }
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
            let input: VecDeque<String> = std::io::stdin()
                .lock()
                .lines()
                .collect::<Result<VecDeque<String>, std::io::Error>>()
                .context("Failed to read from stdin")?;
            let mut buffer = String::new();
            for line in input {
                buffer.push_str(&line);
            }

            println!("{}", buffer);

            if let Ok(signed_update) = serde_json::from_str::<SignedUpdate>(&buffer) {
                fetch_root_key_from_non_ic(&agent, &opts.replica).await?;
                let request_id = agent
                    .update_signed(
                        signed_update.effective_canister_id,
                        signed_update.signed_update,
                    )
                    .await
                    .context("Got an AgentError when send the signed update call")?;
                eprintln!("RequestID: 0x{}", String::from(request_id));
            } else if let Ok(signed_query) = serde_json::from_str::<SignedQuery>(&buffer) {
                let blob = agent
                    .query_signed(
                        signed_query.effective_canister_id,
                        signed_query.signed_query,
                    )
                    .await
                    .context("Got an error when send the signed query call")?;
                print_idl_blob(&blob, &ArgType::Idl, &None)
                    .context("Failed to print query result")?;
            } else if let Ok(signed_request_status) =
                serde_json::from_str::<SignedRequestStatus>(&buffer)
            {
                fetch_root_key_from_non_ic(&agent, &opts.replica).await?;
                let response = agent
                    .request_status_signed(
                        &signed_request_status.request_id,
                        signed_request_status.effective_canister_id,
                        signed_request_status.signed_request_status,
                    )
                    .await
                    .context("Got an error when send the signed request_status call")?;

                match response {
                    agent::RequestStatusResponse::Replied(response) => {
                        print_idl_blob(&response.arg, &ArgType::Idl, &None)
                            .context("Failed to print request_status result")?;
                    }
                    agent::RequestStatusResponse::Rejected(replica_error) => {
                        bail!(
                            r#"The Replica returned an error. reject code: {:?}, reject message: "{}", error code: {}"#,
                            replica_error.reject_code,
                            replica_error.reject_message,
                            replica_error.error_code.unwrap_or_default()
                        );
                    }
                    _ => bail!("Can't get valid status of the request.",),
                }
            } else {
                bail!("Invalid input.");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::Opts;
    use clap::CommandFactory;

    #[test]
    fn valid_command() {
        Opts::command().debug_assert();
    }
}
