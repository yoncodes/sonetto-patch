use serde::Deserialize;
use std::{env, fs, net::Ipv4Addr, path::PathBuf, sync::LazyLock};

#[derive(Clone, Debug, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub ipv4: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyEndpoint {
    pub ipv4: Ipv4Addr,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub game: Endpoint,
    pub tls: Endpoint,
    #[serde(default)]
    pub proxy: Option<ProxyEndpoint>,
}

static CONFIG: LazyLock<Result<ClientConfig, String>> = LazyLock::new(|| {
    let path = env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("sonetto.toml")))
        .unwrap_or_else(|| PathBuf::from("sonetto.toml"));
    let text = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let config: ClientConfig =
        toml::from_str(&text).map_err(|error| format!("invalid {}: {error}", path.display()))?;
    if config.game.host.is_empty() || config.tls.host.is_empty() {
        return Err("endpoint host cannot be empty".to_string());
    }
    Ok(config)
});

pub fn get() -> Result<&'static ClientConfig, &'static str> {
    CONFIG
        .as_ref()
        .map_err(|_| "client configuration unavailable")
}

#[cfg(test)]
mod tests {
    use super::ClientConfig;

    #[test]
    fn parses_independent_sdk_game_and_tls_endpoints() {
        let config: ClientConfig = toml::from_str(
            r#"
            [game]
            host = "reverse1999.example"
            port = 32052
            ipv4 = "192.0.2.10"

            [tls]
            host = "reverse1999.example"
            port = 32053
            "#,
        )
        .unwrap();
        assert_eq!(config.game.port, 32052);
        assert_eq!(config.tls.port, 32053);
        assert_eq!(config.tls.ipv4, None);
        assert!(config.proxy.is_none());
        assert_eq!(config.game.ipv4.unwrap().octets(), [192, 0, 2, 10]);
    }

    #[test]
    fn parses_optional_process_proxy_endpoint() {
        let config: ClientConfig = toml::from_str(
            r#"
            [game]
            host = "reverse1999.example"
            port = 32052

            [tls]
            host = "reverse1999.example"
            port = 32053

            [proxy]
            ipv4 = "127.0.0.1"
            port = 8080
            "#,
        )
        .unwrap();
        let proxy = config.proxy.unwrap();
        assert_eq!(proxy.ipv4.octets(), [127, 0, 0, 1]);
        assert_eq!(proxy.port, 8080);
    }
}
