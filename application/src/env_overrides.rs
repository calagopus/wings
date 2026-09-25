use serde_json::Value;

const PREFIX: &str = "CALAGOPUS_";

#[derive(Default)]
pub struct EnvOverrides {
    pub applied: Vec<String>,
    pub unknown: Vec<String>,
}

/// Resolves `CALAGOPUS_SYSTEM_SFTP_BIND_PORT` style names against the keys that
/// exist in `value`, so single underscores work inside key names
/// (`system.sftp.bind_port`). Longer key matches are tried first, with
/// backtracking when a longer match leads to a dead end.
fn resolve(value: &Value, tokens: &[String]) -> Option<Vec<String>> {
    let Value::Object(object) = value else {
        return None;
    };

    for i in (1..=tokens.len()).rev() {
        let (head, tail) = tokens.split_at(i);
        let key = head.join("_");
        let Some(child) = object.get(&key) else {
            continue;
        };

        if tail.is_empty() {
            return Some(vec![key]);
        }

        if let Some(mut rest) = resolve(child, tail) {
            rest.insert(0, key);
            return Some(rest);
        }
    }

    None
}

fn parse_value(existing: &Value, raw: &str) -> Value {
    if existing.is_string() {
        return Value::String(raw.to_string());
    }

    match serde_norway::from_str::<Value>(raw) {
        Ok(Value::Null) if !raw.trim().is_empty() && !existing.is_null() => {
            Value::String(raw.to_string())
        }
        Ok(value) => value,
        Err(_) => Value::String(raw.to_string()),
    }
}

pub fn apply(config: &mut Value, vars: impl IntoIterator<Item = (String, String)>) -> EnvOverrides {
    let mut overrides = EnvOverrides::default();

    let mut vars = vars
        .into_iter()
        .filter_map(|(name, raw)| {
            let key = name.strip_prefix(PREFIX)?.to_lowercase();
            (!key.is_empty()).then_some((name, key, raw))
        })
        .collect::<Vec<_>>();
    vars.sort();

    for (name, key, raw) in vars {
        let tokens = key.split('_').map(String::from).collect::<Vec<_>>();

        let Some(path) = resolve(config, &tokens) else {
            overrides.unknown.push(name);
            continue;
        };

        let mut target = &mut *config;
        for key in &path {
            target = &mut target[key.as_str()];
        }

        *target = parse_value(target, &raw);
        overrides
            .applied
            .push(format!("{name} -> {}", path.join(".")));
    }

    overrides
}

pub fn apply_to_config(
    config: crate::config::InnerConfig,
) -> Result<(crate::config::InnerConfig, EnvOverrides), anyhow::Error> {
    let vars = std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, _)| name.starts_with(PREFIX))
        .collect::<Vec<_>>();
    if vars.is_empty() {
        return Ok((config, EnvOverrides::default()));
    }

    let mut value = serde_json::to_value(&config)?;
    let overrides = apply(&mut value, vars);

    let config = serde_json::from_value(value).map_err(|err| {
        anyhow::anyhow!(
            "invalid {PREFIX}* environment override ({}): {err}",
            overrides.applied.join(", ")
        )
    })?;

    Ok((config, overrides))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn default_config() -> Value {
        serde_json::to_value(crate::config::InnerConfig::default())
            .expect("config should serialize")
    }

    // apply
    #[test]
    fn underscore_inside_key_resolves_against_real_config() {
        let mut config = default_config();
        let result = apply(
            &mut config,
            vars(&[("CALAGOPUS_SYSTEM_SFTP_BIND_PORT", "2023")]),
        );

        assert_eq!(
            result.applied,
            vec!["CALAGOPUS_SYSTEM_SFTP_BIND_PORT -> system.sftp.bind_port".to_string()]
        );
        assert!(result.unknown.is_empty());
        assert_eq!(config["system"]["sftp"]["bind_port"], json!(2023));

        let parsed: crate::config::InnerConfig =
            serde_json::from_value(config).expect("config should deserialize");
        assert_eq!(parsed.system.sftp.bind_port, 2023);
    }

    #[test]
    fn prefers_longest_key_match() {
        let mut config = json!({ "a": { "b": 1 }, "a_b": 1 });
        let result = apply(&mut config, vars(&[("CALAGOPUS_A_B", "2")]));

        assert_eq!(result.applied, vec!["CALAGOPUS_A_B -> a_b".to_string()]);
        assert_eq!(config, json!({ "a": { "b": 1 }, "a_b": 2 }));
    }

    #[test]
    fn backtracks_when_longer_key_is_a_dead_end() {
        let mut config = json!({ "a_b": { "x": 1 }, "a": { "b_c": 1 } });
        let result = apply(&mut config, vars(&[("CALAGOPUS_A_B_C", "2")]));

        assert_eq!(result.applied, vec!["CALAGOPUS_A_B_C -> a.b_c".to_string()]);
        assert!(result.unknown.is_empty());
        assert_eq!(config, json!({ "a_b": { "x": 1 }, "a": { "b_c": 2 } }));
    }

    #[test]
    fn unresolvable_names_are_unknown_and_leave_config_untouched() {
        let original = json!({ "a": "x", "list": [{ "b": 1 }], "obj": { "c": 1 } });
        let mut config = original.clone();
        let result = apply(
            &mut config,
            vars(&[
                ("CALAGOPUS_A_B", "1"),
                ("CALAGOPUS_LIST_B", "1"),
                ("CALAGOPUS_OBJ_NEW", "1"),
                ("CALAGOPUS_MISSING", "1"),
            ]),
        );

        assert!(result.applied.is_empty());
        let mut unknown = result.unknown.clone();
        unknown.sort();
        assert_eq!(
            unknown,
            vec![
                "CALAGOPUS_A_B".to_string(),
                "CALAGOPUS_LIST_B".to_string(),
                "CALAGOPUS_MISSING".to_string(),
                "CALAGOPUS_OBJ_NEW".to_string(),
            ]
        );
        assert_eq!(config, original);
    }

    #[test]
    fn ignores_unprefixed_and_bare_prefix_vars() {
        let original = json!({ "path": "x", "token": "y" });
        let mut config = original.clone();
        let result = apply(
            &mut config,
            vars(&[("PATH", "/bin"), ("CALAGOPUS_", "1"), ("TOKEN", "z")]),
        );

        assert!(result.applied.is_empty());
        assert!(result.unknown.is_empty());
        assert_eq!(config, original);
    }

    #[test]
    fn string_fields_store_raw_value_verbatim() {
        let mut config = default_config();
        apply(
            &mut config,
            vars(&[
                ("CALAGOPUS_TOKEN", "12345"),
                ("CALAGOPUS_SYSTEM_DATA", "/srv/data: x"),
                ("CALAGOPUS_DOCKER_FIREWALL_BACKEND", "nftables"),
            ]),
        );

        assert_eq!(config["token"], json!("12345"));
        assert_eq!(config["system"]["data"], json!("/srv/data: x"));

        let parsed: crate::config::InnerConfig =
            serde_json::from_value(config).expect("config should deserialize");
        assert!(matches!(
            parsed.docker.firewall.backend,
            crate::server::firewall::FirewallBackendKind::Nftables
        ));
    }

    #[test]
    fn non_string_fields_parse_as_yaml() {
        let mut config = json!({ "flag": false, "list": [], "port": 1, "ratio": 1 });
        apply(
            &mut config,
            vars(&[
                ("CALAGOPUS_FLAG", "true"),
                ("CALAGOPUS_LIST", "[1, \"two\"]"),
                ("CALAGOPUS_PORT", "8080"),
                ("CALAGOPUS_RATIO", "0.5"),
            ]),
        );

        assert_eq!(
            config,
            json!({ "flag": true, "list": [1, "two"], "port": 8080, "ratio": 0.5 })
        );
    }

    #[test]
    fn unparseable_or_null_yaml_falls_back_to_raw_string() {
        let mut config = json!({ "a": 1, "b": 1, "c": null });
        apply(
            &mut config,
            vars(&[
                ("CALAGOPUS_A", "[unclosed"),
                ("CALAGOPUS_B", "null"),
                ("CALAGOPUS_C", "null"),
            ]),
        );

        assert_eq!(config, json!({ "a": "[unclosed", "b": "null", "c": null }));
    }

    #[test]
    fn applied_is_sorted_by_name() {
        let mut config = json!({ "a": 1, "b": 1, "c": 1 });
        let result = apply(
            &mut config,
            vars(&[
                ("CALAGOPUS_C", "3"),
                ("CALAGOPUS_A", "1"),
                ("CALAGOPUS_B", "2"),
            ]),
        );

        assert_eq!(
            result.applied,
            vec![
                "CALAGOPUS_A -> a".to_string(),
                "CALAGOPUS_B -> b".to_string(),
                "CALAGOPUS_C -> c".to_string(),
            ]
        );
    }
}
