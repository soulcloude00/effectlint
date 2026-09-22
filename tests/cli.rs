use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_effectlint"))
}

#[test]
fn baseline_emits_only_new_scope() {
    let output = bin()
        .args([
            "tests/conformance/scope-expansion-head.yaml",
            "--baseline",
            "tests/conformance/scope-expansion-base.yaml",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("repo:write"));
    assert!(!text.contains("repo:read"));
}

#[test]
fn policy_fails_on_removed_approval() {
    let output = bin()
        .args([
            "tests/conformance/approval-removal.yaml",
            "--policy",
            "effectlint.policy.example.yml",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("policy denied"));
}

#[test]
fn sarif_is_well_formed() {
    let output = bin()
        .args(["tests/conformance/tool-poisoning.yaml", "--format", "sarif"])
        .output()
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(
        value["runs"][0]["results"][0]["ruleId"],
        "tool.untrusted_instructions"
    );
}
