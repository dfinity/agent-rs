use super::utils::create_agent;

#[actix_rt::test]
async fn status_endpoint_works() -> Result<(), String> {
    let agent = create_agent().await?;
    agent.ping_once().await?;

    Ok(())
}

#[actix_rt::test]
async fn status_endpoint_is_expected() -> Result<(), String> {
    let agent = create_agent().await?;
    let status = agent.ping_once().await?;

    match status {
        serde_cbor::Value::Map(map) => {
            let key = serde_cbor::Value::from("ic_api_version".to_string());
            assert_eq!(map.get(  &key), Some(&serde_cbor::Value::from("0.8.2".to_string())));
        },
        x => assert!(false, "Invalid status return: {:?}", x),
    }

    Ok(())
}
