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
    /// Where custom resolvers are persisted (JSON list of {name, ip}).
    pub custom_resolvers_path: PathBuf,
}

/// JSON shape for persisted custom resolvers; Resolver itself stays
/// Debug/Clone only.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CustomResolverEntry {
    name: String,
    ip: IpAddr,
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

/// Private infra DNS resolvers (time lab). Not part of the public builtins.
pub fn time_resolvers() -> Vec<Resolver> {
    let list: &[(&str, &str)] = &[
        ("GLEN-R1", "210.19.6.97"),
        ("UPM-R2", "210.19.6.129"),
        ("GLEN-A1", "210.19.6.100"),
        ("UPM-A2", "210.19.6.132"),
        ("ANS-ANYCAST-1", "210.19.6.85"),
        ("ANS-ANYCAST-2", "210.19.6.86"),
        ("GLEN-C1", "210.19.6.103"),
        ("GLEN-C2", "210.19.6.106"),
        ("GLEN-C3", "210.19.6.109"),
        ("UPM-C1", "210.19.6.135"),
        ("UPM-C2", "210.19.6.138"),
        ("UPM-C3", "210.19.6.141"),
        ("CACHE-ANYCAST-1", "210.19.6.81"),
        ("CACHE-ANYCAST-2", "210.19.6.82"),
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

fn default_custom_resolvers_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dnsdoc")
        .join("custom_resolvers.json")
}

/// Load persisted custom resolvers; empty Vec on any read/parse error
/// (missing file is normal on first run).
pub fn load_custom_resolvers(path: &std::path::Path) -> Vec<Resolver> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let Ok(entries) = serde_json::from_str::<Vec<CustomResolverEntry>>(&text) else {
        return vec![];
    };
    entries
        .into_iter()
        .map(|e| Resolver { name: e.name, ip: e.ip })
        .collect()
}

/// Persist custom resolvers as JSON, creating the parent dir if missing.
pub fn save_custom_resolvers(path: &std::path::Path, resolvers: &[Resolver]) -> std::io::Result<()> {
    let entries: Vec<CustomResolverEntry> = resolvers
        .iter()
        .map(|r| CustomResolverEntry { name: r.name.clone(), ip: r.ip })
        .collect();
    let text = serde_json::to_string(&entries)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
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
        Profile { name: "time".into(), resolvers: time_resolvers() },
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
        custom_resolvers_path: default_custom_resolvers_path(),
    }
}

impl Config {
    pub fn load() -> Config {
        let path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dnsdoc")
            .join("config.toml");
        let toml_str = std::fs::read_to_string(path).unwrap_or_default();
        let mut cfg = parse(&toml_str);

        // Custom resolvers come from disk, not the toml — loaded here so the
        // pure `parse()` (and its tests) stay deterministic.
        let custom_path = default_custom_resolvers_path();
        let custom = load_custom_resolvers(&custom_path);
        cfg.custom_resolvers_path = custom_path;
        cfg.profiles.insert(3, Profile { name: "custom".into(), resolvers: custom });
        cfg
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
        assert_eq!(names, ["all", "global", "privacy", "time"]);
        assert_eq!(cfg.profiles[1].resolvers.len(), 8);
        assert_eq!(cfg.profiles[2].resolvers.len(), 3);
        assert_eq!(cfg.profiles[3].resolvers.len(), 14);
    }

    #[test]
    fn time_profile_has_expected_resolvers() {
        let cfg = parse("");
        let time = cfg.profiles.iter().find(|p| p.name == "time").unwrap();
        assert_eq!(time.resolvers.len(), 14);
        assert_eq!(time.resolvers[0].name, "GLEN-R1");
        assert_eq!(time.resolvers[0].ip, "210.19.6.97".parse::<IpAddr>().unwrap());
        assert_eq!(time.resolvers[13].name, "CACHE-ANYCAST-2");
        assert_eq!(time.resolvers[13].ip, "210.19.6.82".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn custom_resolvers_roundtrip_disk() {
        let dir = std::env::temp_dir().join(format!("dnsdoc-test-{}", std::process::id()));
        let path = dir.join("custom_resolvers.json");
        let r = Resolver { name: "lab".into(), ip: "10.1.2.3".parse().unwrap() };
        save_custom_resolvers(&path, &[r]).unwrap();
        let loaded = load_custom_resolvers(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "lab");
        assert_eq!(loaded[0].ip, "10.1.2.3".parse::<IpAddr>().unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_custom_resolvers_missing_file_is_empty() {
        let path = std::env::temp_dir().join("dnsdoc-missing-resolvers.json");
        let _ = std::fs::remove_file(&path);
        assert!(load_custom_resolvers(&path).is_empty());
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
