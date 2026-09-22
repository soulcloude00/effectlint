use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    version,
    about = "Emit a capability BOM from agent or deployment configuration"
)]
struct Cli {
    /// JSON or YAML configuration to scan.
    input: PathBuf,
    /// Output format.
    #[arg(long, value_enum, default_value = "json")]
    format: Format,
    /// Optional base configuration. Emit only authority new in INPUT.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// Optional YAML/JSON policy. Denied findings make the command fail.
    #[arg(long)]
    policy: Option<PathBuf>,
}

#[derive(Clone, ValueEnum)]
enum Format {
    Json,
    Sarif,
}

#[derive(Debug, Serialize)]
struct Bom {
    schema_version: &'static str,
    source: String,
    capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct Capability {
    subject: String,
    effect: String,
    authority: String,
    evidence: String,
}

#[derive(Debug, Default, Deserialize)]
struct Policy {
    #[serde(default)]
    deny_effects: BTreeSet<String>,
    #[serde(default)]
    deny_authorities: BTreeSet<String>,
}

impl Policy {
    fn load(path: &Path) -> Result<Self> {
        let value = parse_config(path)?;
        serde_json::from_value(value).context("parse effectlint policy")
    }

    fn denies(&self, capability: &Capability) -> bool {
        self.deny_effects.contains(&capability.effect)
            || self.deny_authorities.contains(&capability.authority)
    }
}

fn parse_config(path: &Path) -> Result<Value> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    match path.extension().and_then(|x| x.to_str()) {
        Some("yaml" | "yml") => serde_yaml::from_str(&raw).context("parse YAML configuration"),
        _ => serde_json::from_str(&raw).context("parse JSON configuration"),
    }
}

fn push(
    caps: &mut Vec<Capability>,
    subject: &str,
    effect: &str,
    authority: String,
    evidence: String,
) {
    caps.push(Capability {
        subject: subject.into(),
        effect: effect.into(),
        authority,
        evidence,
    });
}

fn strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

fn walk(value: &Value, path: &str, caps: &mut Vec<Capability>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let here = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                let lower = key.to_ascii_lowercase();
                if matches!(lower.as_str(), "scopes" | "oauth_scopes" | "oauthscopes") {
                    for scope in strings(child) {
                        push(
                            caps,
                            &here,
                            "oauth.scope",
                            scope.clone(),
                            format!("{here}: {scope}"),
                        );
                    }
                }
                if matches!(lower.as_str(), "audience" | "aud" | "allowed_audiences") {
                    for audience in strings(child) {
                        push(
                            caps,
                            &here,
                            "token.audience",
                            audience.clone(),
                            format!("{here}: {audience}"),
                        );
                    }
                }
                if matches!(
                    lower.as_str(),
                    "serviceaccount"
                        | "service_account"
                        | "rolearn"
                        | "role_arn"
                        | "cloudaccount"
                        | "cloud_account"
                        | "projectid"
                        | "project_id"
                        | "subscriptionid"
                        | "subscription_id"
                ) {
                    if let Some(identity) = child.as_str() {
                        push(
                            caps,
                            &here,
                            "deployment.identity",
                            identity.into(),
                            format!("{here}: {identity}"),
                        );
                    }
                }
                if matches!(
                    lower.as_str(),
                    "approval_required" | "requireapproval" | "require_approval" | "human_approval"
                ) && child == &Value::Bool(false)
                {
                    push(
                        caps,
                        &here,
                        "approval.bypass",
                        "approval disabled".into(),
                        format!("{here}: false"),
                    );
                }
                if matches!(lower.as_str(), "description" | "instructions" | "prompt") {
                    if let Some(text) = child.as_str() {
                        let t = text.to_ascii_lowercase();
                        if [
                            "ignore previous",
                            "bypass approval",
                            "exfiltrate",
                            "send secrets",
                        ]
                        .iter()
                        .any(|needle| t.contains(needle))
                        {
                            push(
                                caps,
                                &here,
                                "tool.untrusted_instructions",
                                "instruction-like tool metadata".into(),
                                format!("suspicious text at {here}"),
                            );
                        }
                    }
                }
                walk(child, &here, caps);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{path}[{index}]"), caps);
            }
        }
        _ => {}
    }
}

fn scan(path: &Path) -> Result<Bom> {
    let config = parse_config(path)?;
    let mut capabilities = Vec::new();

    if let Some(servers) = config.get("mcpServers").and_then(Value::as_object) {
        for (name, server) in servers {
            if let Some(command) = server.get("command").and_then(Value::as_str) {
                push(
                    &mut capabilities,
                    name,
                    "process.spawn",
                    command.into(),
                    format!("mcpServers.{name}.command: {command}"),
                );
            }
            let args = server.get("args").map(strings).unwrap_or_default();
            for endpoint in args
                .iter()
                .filter(|arg| arg.starts_with("http://") || arg.starts_with("https://"))
            {
                push(
                    &mut capabilities,
                    name,
                    "network.connect",
                    endpoint.clone(),
                    format!("mcpServers.{name}.args: {endpoint}"),
                );
            }
            if let Some(env) = server.get("env").and_then(Value::as_object) {
                for key in env.keys().filter(|key| is_sensitive_env(key)) {
                    push(
                        &mut capabilities,
                        name,
                        "secret.read",
                        key.clone(),
                        format!("mcpServers.{name}.env key: {key}"),
                    );
                }
            }
        }
    }
    walk(&config, "", &mut capabilities);
    capabilities.sort();
    capabilities.dedup();
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

fn only_new(mut head: Bom, base: Bom) -> Bom {
    let known: BTreeSet<_> = base.capabilities.into_iter().collect();
    head.capabilities.retain(|cap| !known.contains(cap));
    head
}

fn sarif(bom: &Bom) -> Value {
    let results: Vec<_> = bom.capabilities.iter().map(|cap| serde_json::json!({
        "ruleId": cap.effect,
        "level": "warning",
        "message": {"text": format!("{} introduces {} ({})", cap.subject, cap.effect, cap.authority)},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": bom.source}}}]
    })).collect();
    serde_json::json!({"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"effectlint","informationUri":"https://github.com/soulcloude00/effectlint","rules":[]}},"results":results}]})
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut bom = scan(&cli.input)?;
    if let Some(baseline) = &cli.baseline {
        bom = only_new(bom, scan(baseline)?);
    }
    let denied: Vec<_> = cli
        .policy
        .as_ref()
        .map(|path| Policy::load(path.as_path()))
        .transpose()?
        .map(|policy| {
            bom.capabilities
                .iter()
                .filter(|cap| policy.denies(cap))
                .collect()
        })
        .unwrap_or_default();
    let output = match cli.format {
        Format::Json => serde_json::to_value(&bom)?,
        Format::Sarif => sarif(&bom),
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    if !denied.is_empty() {
        bail!("policy denied {} new authority finding(s)", denied.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sensitive_names_are_detected() {
        assert!(is_sensitive_env("GITHUB_TOKEN"));
        assert!(!is_sensitive_env("LOG_LEVEL"));
    }
    #[test]
    fn widening_is_a_new_capability() {
        let a = Capability {
            subject: "oauth.scopes".into(),
            effect: "oauth.scope".into(),
            authority: "repo:read".into(),
            evidence: "a".into(),
        };
        let b = Capability {
            subject: "oauth.scopes".into(),
            effect: "oauth.scope".into(),
            authority: "repo:write".into(),
            evidence: "b".into(),
        };
        let known: BTreeSet<_> = [a].into_iter().collect();
        assert!(!known.contains(&b));
    }
}
