use std::net::IpAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Resolver {
    pub name: String,
    pub ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub resolvers: Vec<Resolver>,
    pub poll_interval_secs: u64,
    pub history_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawResolver {
    name: String,
    ip: IpAddr,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    resolver: Vec<RawResolver>,
    poll_interval_secs: Option<u64>,
}

pub fn builtin_resolvers() -> Vec<Resolver> {
    let list: &[(&str, &str)] = &[
        ("Google", "8.8.8.8"),
        ("Google-2", "8.8.4.4"),
        ("Cloudflare", "1.1.1.1"),
        ("Cloudflare-2", "1.0.0.1"),
        ("Quad9", "9.9.9.9"),
        ("Quad9-2", "149.112.112.112"),
        ("OpenDNS", "208.67.222.222"),
        ("OpenDNS-2", "208.67.220.220"),
        ("AdGuard", "94.140.14.14"),
        ("DNS.SB", "185.222.222.222"),
        ("Comodo", "8.26.56.26"),
        ("CleanBrowsing", "185.228.168.9"),
        ("Level3", "4.2.2.1"),
        ("Verisign", "64.6.64.6"),
        ("Yandex", "77.88.8.8"),
        ("ControlD", "76.76.2.0"),
    ];
    list.iter()
        .map(|(name, ip)| Resolver {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
        })
        .collect()
}

fn default_history_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dns-tester")
        .join("history.jsonl")
}

fn parse(toml_str: &str) -> Config {
    let raw: RawConfig = toml::from_str(toml_str).unwrap_or(RawConfig {
        resolver: vec![],
        poll_interval_secs: None,
    });
    let mut resolvers = builtin_resolvers();
    for r in raw.resolver {
        resolvers.push(Resolver { name: r.name, ip: r.ip });
    }
    Config {
        resolvers,
        poll_interval_secs: raw.poll_interval_secs.unwrap_or(60),
        history_path: default_history_path(),
    }
}

impl Config {
    pub fn load() -> Config {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dns-tester")
            .join("config.toml");
        let toml_str = std::fs::read_to_string(path).unwrap_or_default();
        parse(&toml_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_resolver_appended_to_builtins() {
        let cfg = parse("poll_interval_secs = 30\n[[resolver]]\nname = \"MyISP\"\nip = \"10.0.0.53\"\n");
        assert_eq!(cfg.poll_interval_secs, 30);
        assert_eq!(cfg.resolvers.len(), builtin_resolvers().len() + 1);
        assert_eq!(cfg.resolvers.last().unwrap().name, "MyISP");
    }

    #[test]
    fn bad_toml_falls_back_to_defaults() {
        let cfg = parse("not valid toml [[[");
        assert_eq!(cfg.poll_interval_secs, 60);
        assert_eq!(cfg.resolvers.len(), builtin_resolvers().len());
    }
}
