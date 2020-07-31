use ic_agent::{Agent, AgentConfig};

pub async fn create_agent() -> Result<Agent, String>
{
    Ok(ic_agent::Agent::new(AgentConfig {
        url: "http://127.0.0.1:8001",
        ..AgentConfig::default()
    })?)
}
