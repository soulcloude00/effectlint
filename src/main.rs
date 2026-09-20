use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Emit a capability BOM from an MCP server configuration"
)]
struct Cli {
    /// MCP JSON configuration to scan.
    input: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value = "json")]
    format: Format,
    /// Optional base configuration. When set, emit only capabilities new in INPUT.
    #[arg(long)]
    baseline: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Sarif,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McpConfig {
    #[serde(default)]
    mcp_servers: std::collections::BTreeMap<String, Server>,
}

#[derive(Debug, Deserialize)]
struct Server {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct Bom {
    schema_version: &'static str,
    source: String,
    capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Capability {
    server: String,
    effect: &'static str,
    authority: String,
    evidence: String,
}

fn scan(path: &PathBuf) -> Result<Bom> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config: McpConfig = serde_json::from_str(&raw).context("parse MCP JSON")?;
    let mut capabilities = Vec::new();

    for (name, server) in config.mcp_servers {
        capabilities.push(Capability {
            server: name.clone(),
            effect: "process.spawn",
            authority: server.command.clone(),
            evidence: format!("command: {}", server.command),
        });

        let tokens: BTreeSet<_> = server.args.iter().map(String::as_str).collect();
        if tokens
            .iter()
            .any(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
        {
            capabilities.push(Capability {
                server: name.clone(),
                effect: "network.connect",
                authority: "remote endpoint supplied in args".into(),
                evidence: server.args.join(" "),
            });
        }

        for key in server.env.keys() {
            if is_sensitive_env(key) {
                capabilities.push(Capability {
                    server: name.clone(),
                    effect: "secret.read",
                    authority: key.clone(),
                    evidence: format!("env key: {key}"),
                });
            }
        }
    }

    Ok(Bom {
        schema_version: "effectlint.capability-bom/v1alpha1",
        source: path.display().to_string(),
        capabilities,
    })
}

fn is_sensitive_env(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    ["TOKEN", "SECRET", "PASSWORD", "API_KEY", "PRIVATE_KEY"]
        .iter()
        .any(|marker| upper.contains(marker))
}

fn sarif(bom: &Bom) -> serde_json::Value {
    let results: Vec<_> = bom.capabilities.iter().map(|cap| serde_json::json!({
        "ruleId": cap.effect,
        "level": "note",
        "message": {"text": format!("{} grants {} ({})", cap.server, cap.effect, cap.authority)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": bom.source}}}]
    })).collect();
    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "effectlint", "informationUri": "https://github.com/haresh-k/effectlint", "rules": []}}, "results": results}]
    })
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut bom = scan(&cli.input)?;
    if let Some(baseline) = &cli.baseline {
        let base = scan(baseline)?;
        let known: BTreeSet<_> = base.capabilities.into_iter().collect();
        bom.capabilities.retain(|cap| !known.contains(cap));
    }
    let output = match cli.format {
        Format::Json => serde_json::to_value(&bom)?,
        Format::Sarif => sarif(&bom),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn baseline_filter_uses_full_capability_identity() {
        let a = Capability {
            server: "one".into(),
            effect: "network.connect",
            authority: "a".into(),
            evidence: "a".into(),
        };
        let b = Capability {
            server: "one".into(),
            effect: "network.connect",
            authority: "b".into(),
            evidence: "b".into(),
        };
        let known: BTreeSet<_> = [a].into_iter().collect();
        assert!(!known.contains(&b));
    }

    #[test]
    fn sensitive_names_are_detected() {
        assert!(is_sensitive_env("GITHUB_TOKEN"));
        assert!(is_sensitive_env("db_password"));
        assert!(!is_sensitive_env("LOG_LEVEL"));
    }
}
