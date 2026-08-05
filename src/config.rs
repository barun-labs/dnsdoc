use std::net::IpAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Resolver {
    pub name: String,
    pub ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub resolvers: Vec<Resolver>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub profiles: Vec<Profile>,
    pub poll_interval_secs: u64,
    pub history_path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct RawResolver {
    name: String,
    ip: IpAddr,
}

#[derive(Debug, Deserialize)]
struct RawProfile {
    name: String,
    #[serde(default)]
    resolvers: Vec<RawResolver>,
}

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    resolver: Vec<RawResolver>,
    #[serde(default)]
    profile: Vec<RawProfile>,
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
    ];
    list.iter()
        .map(|(name, ip)| Resolver {
            name: name.to_string(),
            ip: ip.parse().unwrap(),
        })
        .collect()
}

/// Subset of the builtins by name.
fn preset(names: &[&str]) -> Vec<Resolver> {
    builtin_resolvers()
        .into_iter()
        .filter(|r| names.contains(&r.name.as_str()))
        .collect()
}

fn default_history_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dnsdoc")
        .join("history.jsonl")
}

fn parse(toml_str: &str) -> Config {
    let raw: RawConfig = toml::from_str(toml_str).unwrap_or(RawConfig {
        resolver: vec![],
        profile: vec![],
        poll_interval_secs: None,
    });

    // Profile 0 ("all"): every builtin plus any top-level [[resolver]] entries.
    let mut all = builtin_resolvers();
    for r in raw.resolver {
        all.push(Resolver { name: r.name, ip: r.ip });
    }
    let mut profiles = vec![
        Profile { name: "all".into(), resolvers: all },
        Profile {
            name: "global".into(),
            resolvers: preset(&[
                "Google", "Google-2", "Cloudflare", "Cloudflare-2", "Quad9", "Quad9-2",
                "OpenDNS", "OpenDNS-2",
            ]),
        },
        Profile {
            name: "privacy".into(),
            resolvers: preset(&["Quad9", "Quad9-2", "AdGuard"]),
        },
    ];
    for p in raw.profile {
        profiles.push(Profile {
            name: p.name,
            resolvers: p
                .resolvers
                .into_iter()
                .map(|r| Resolver { name: r.name, ip: r.ip })
                .collect(),
        });
    }

    Config {
        profiles,
        poll_interval_secs: raw.poll_interval_secs.unwrap_or(60),
        history_path: default_history_path(),
    }
}

impl Config {
    pub fn load() -> Config {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dnsdoc")
            .join("config.toml");
        let toml_str = std::fs::read_to_string(path).unwrap_or_default();
        parse(&toml_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_resolver_appended_to_all_profile() {
        let cfg = parse("poll_interval_secs = 30\n[[resolver]]\nname = \"MyISP\"\nip = \"10.0.0.53\"\n");
        assert_eq!(cfg.poll_interval_secs, 30);
        let all = &cfg.profiles[0];
        assert_eq!(all.name, "all");
        assert_eq!(all.resolvers.len(), builtin_resolvers().len() + 1);
        assert_eq!(all.resolvers.last().unwrap().name, "MyISP");
    }

    #[test]
    fn bad_toml_falls_back_to_defaults() {
        let cfg = parse("not valid toml [[[");
        assert_eq!(cfg.poll_interval_secs, 60);
        assert_eq!(cfg.profiles[0].resolvers.len(), builtin_resolvers().len());
    }

    #[test]
    fn presets_exist_with_expected_sizes() {
        let cfg = parse("");
        let names: Vec<&str> = cfg.profiles.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["all", "global", "privacy"]);
        assert_eq!(cfg.profiles[1].resolvers.len(), 8);
        assert_eq!(cfg.profiles[2].resolvers.len(), 3);
    }

    #[test]
    fn user_profiles_appended_after_presets() {
        let cfg = parse(
            "[[profile]]\nname = \"home\"\nresolvers = [{ name = \"MyISP\", ip = \"10.0.0.53\" }]\n",
        );
        let home = cfg.profiles.last().unwrap();
        assert_eq!(home.name, "home");
        assert_eq!(home.resolvers.len(), 1);
        assert_eq!(home.resolvers[0].name, "MyISP");
    }
}
