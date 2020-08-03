use ic_agent::{Agent, AgentConfig};

pub async fn create_agent() -> Result<Agent, String>
{
    let port_env = std::env::var("IC_REF_PORT").expect("Need to specify the IC_REF_PORT environment variable.");
    let port = port_env.parse::<u32>().expect("Could not parse the IC_REF_PORT environment variable as an integer.");

    Ok(ic_agent::Agent::new(AgentConfig {
        url: &format!("http://127.0.0.1:{}", port),
        ..AgentConfig::default()
    })?)
}
