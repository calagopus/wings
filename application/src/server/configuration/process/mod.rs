use compact_str::ToCompactString;
use serde::Deserialize;
use serde_default::DefaultFromSerde;
use std::path::Path;
use utoipa::ToSchema;

mod ini;
mod json;
mod plain;
mod properties;
mod toml;
mod xml;
mod yaml;

const MAX_CONFIGURATION_FILE_SIZE: u64 = 1024 * 1024;

fn true_fn() -> bool {
    true
}

#[derive(ToSchema, Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "lowercase")]
#[schema(rename_all = "lowercase")]
pub enum ServerConfigurationFileParser {
    File,
    #[serde(alias = "yml")]
    Yaml,
    Properties,
    Ini,
    Json,
    Xml,
    Toml,
}

#[derive(ToSchema, Deserialize, Clone, Debug)]
pub struct ServerConfigurationFileReplacement {
    pub r#match: compact_str::CompactString,
    pub if_value: Option<compact_str::CompactString>,
    #[schema(value_type = bool)]
    pub insert_new: Option<bool>,
    #[serde(default = "true_fn")]
    pub update_existing: bool,
    #[serde(alias = "value")]
    pub replace_with: serde_json::Value,
}

pub enum Replacement {
    Value,
    Substituted(compact_str::CompactString),
}

impl Replacement {
    pub fn text(self, value: compact_str::CompactString) -> compact_str::CompactString {
        match self {
            Self::Value => value,
            Self::Substituted(text) => text,
        }
    }
}

enum IfValue {
    Exact(compact_str::CompactString),
    Regex(regex::Regex),
    Unusable,
}

pub struct ResolvedReplacement<'a> {
    pub server: &'a crate::server::Server,
    pub replacement: &'a ServerConfigurationFileReplacement,
    pub value: compact_str::CompactString,
    pub insert_new: bool,
    pub update_existing: bool,
    if_value: Option<IfValue>,
}

impl<'a> ResolvedReplacement<'a> {
    pub async fn new(
        server: &'a crate::server::Server,
        replacement: &'a ServerConfigurationFileReplacement,
        default_insert_new: bool,
    ) -> Result<Self, anyhow::Error> {
        let value =
            ServerConfigurationFile::replace_all_placeholders(server, &replacement.replace_with)
                .await?;

        let if_value = replacement.if_value.as_ref().map(|if_value| {
            let Some(pattern) = if_value.strip_prefix("regex:") else {
                return IfValue::Exact(if_value.clone());
            };

            match regex::Regex::new(pattern) {
                Ok(regex) => IfValue::Regex(regex),
                Err(err) => {
                    tracing::warn!(
                        server = %server.uuid,
                        "if_value for '{}' is not a valid regex, no replacement will apply: {:#?}",
                        replacement.r#match, err
                    );

                    IfValue::Unusable
                }
            }
        });

        Ok(Self {
            server,
            replacement,
            value,
            insert_new: replacement.insert_new.unwrap_or(default_insert_new),
            update_existing: replacement.update_existing,
            if_value,
        })
    }

    fn apply_if_value(&self, existing: &str, value: &str) -> Option<Replacement> {
        match self.if_value.as_ref()? {
            IfValue::Unusable => None,
            IfValue::Regex(regex) => regex
                .is_match(existing)
                .then(|| Replacement::Substituted(regex.replace_all(existing, value).into())),
            IfValue::Exact(if_value) => {
                if existing != if_value {
                    tracing::debug!(
                        server = %self.server.uuid,
                        "skipping replacement for '{}': value '{}' != '{}'",
                        self.replacement.r#match, existing, if_value
                    );

                    return None;
                }

                Some(Replacement::Value)
            }
        }
    }

    fn gate_with(&self, existing: Option<&str>, value: &str) -> Option<Replacement> {
        if existing.is_some() {
            if !self.update_existing {
                return None;
            }
        } else if !self.insert_new {
            return None;
        }

        if self.if_value.is_none() {
            return Some(Replacement::Value);
        }

        let Some(existing) = existing else {
            tracing::debug!(
                server = %self.server.uuid,
                "skipping replacement for '{}': nothing exists to match if_value against",
                self.replacement.r#match
            );

            return None;
        };

        self.apply_if_value(existing, value)
    }

    pub fn gate(&self, existing: Option<&str>) -> Option<Replacement> {
        self.gate_with(existing, &self.value)
    }

    pub fn text(&self, existing: Option<&str>) -> Option<compact_str::CompactString> {
        Some(self.gate(existing)?.text(self.value.clone()))
    }

    pub fn text_with(
        &self,
        existing: Option<&str>,
        value: &str,
    ) -> Option<compact_str::CompactString> {
        Some(self.gate_with(existing, value)?.text(value.into()))
    }
}

#[derive(ToSchema, Deserialize, Clone, Debug)]
pub struct ServerConfigurationFile {
    pub file: compact_str::CompactString,
    #[serde(default = "true_fn")]
    pub create_new: bool,
    pub parser: ServerConfigurationFileParser,
    #[serde(default)]
    pub replace: Vec<ServerConfigurationFileReplacement>,
}

impl ServerConfigurationFile {
    async fn lookup_value(
        server: &crate::server::Server,
        replacement: &serde_json::Value,
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        let value = match replacement {
            serde_json::Value::String(s) => s.as_str(),
            serde_json::Value::Number(n) => return Ok(n.to_compact_string()),
            serde_json::Value::Bool(b) => return Ok(b.to_compact_string()),
            serde_json::Value::Null => return Ok(compact_str::CompactString::default()),
            _ => return Ok(replacement.to_compact_string()),
        };

        if !value.starts_with("{{") || !value.ends_with("}}") {
            return Ok(value.to_compact_string());
        }

        let variable = value.trim_start_matches("{{").trim_end_matches("}}").trim();

        tracing::debug!(
            server = %server.uuid,
            "looking up variable: {}",
            variable
        );

        let parts: Vec<&str> = variable.split('.').collect();
        let (Some(section), Some(section_slice)) = (parts.first(), parts.get(1..)) else {
            tracing::error!(
                server = %server.uuid,
                "empty variable path"
            );
            return Ok(compact_str::CompactString::default());
        };

        match *section {
            "server" => Self::lookup_server_variable(server, section_slice).await,
            "config" => Self::lookup_config_variable(server, section_slice),
            "env" | "environment" => {
                let Some(env_var) = parts.get(1) else {
                    return Ok(compact_str::CompactString::default());
                };

                let config = server.configuration.read().await;

                Ok(Self::lookup_environment_variable(
                    server,
                    &config.environment,
                    env_var,
                ))
            }
            part => {
                tracing::error!(
                    server = %server.uuid,
                    "unknown variable prefix: {}",
                    part
                );
                Ok(compact_str::CompactString::default())
            }
        }
    }

    fn lookup_environment_variable(
        server: &crate::server::Server,
        environment: &std::collections::HashMap<compact_str::CompactString, serde_json::Value>,
        name: &str,
    ) -> compact_str::CompactString {
        match environment.get(name) {
            Some(value) => value
                .as_str()
                .map_or_else(|| value.to_compact_string(), |v| v.into()),
            None => {
                tracing::warn!(
                    server = %server.uuid,
                    "environment variable not found: {}",
                    name
                );

                compact_str::CompactString::default()
            }
        }
    }

    fn unknown_server_variable(
        server: &crate::server::Server,
        parts: &[&str],
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        tracing::error!(
            server = %server.uuid,
            "unknown server variable: server.{}",
            parts.join(".")
        );

        Ok(compact_str::CompactString::default())
    }

    async fn lookup_server_variable(
        server: &crate::server::Server,
        parts: &[&str],
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        let Some(section) = parts.first() else {
            return Ok(compact_str::CompactString::default());
        };

        let config = server.configuration.read().await;

        match *section {
            "uuid" => Ok(config.uuid.to_compact_string()),
            "suspended" => Ok(config.suspended.to_compact_string()),
            "invocation" => Ok(config.invocation.clone()),
            "skip_egg_scripts" => Ok(config.skip_egg_scripts.to_compact_string()),
            "rebuild" => Ok(false.to_compact_string()),
            "meta" => match parts.get(1) {
                Some(&"name") => Ok(config.meta.name.clone()),
                Some(&"description") => Ok(config.meta.description.clone()),
                _ => Self::unknown_server_variable(server, parts),
            },
            "container" => match parts.get(1) {
                Some(&"image") => Ok(config.container.image.clone()),
                Some(&"requires_rebuild") => Ok(false.to_compact_string()),
                _ => Self::unknown_server_variable(server, parts),
            },
            "egg" => match parts.get(1) {
                Some(&"id") => Ok(config.egg.id.to_compact_string()),
                _ => Self::unknown_server_variable(server, parts),
            },
            "service" => match parts.get(1) {
                Some(&"egg") => Ok(config.egg.id.to_compact_string()),
                Some(&"skip_scripts") => Ok(config.skip_egg_scripts.to_compact_string()),
                _ => Self::unknown_server_variable(server, parts),
            },
            "labels" => match parts.get(1..) {
                Some(label) if !label.is_empty() => Ok(config
                    .labels
                    .get(&label.join("."))
                    .map(|value| value.as_str().into())
                    .unwrap_or_default()),
                _ => Self::unknown_server_variable(server, parts),
            },
            "mounts" => {
                let Some(index) = parts.get(1).and_then(|index| index.parse::<usize>().ok()) else {
                    return Self::unknown_server_variable(server, parts);
                };
                let Some(mount) = config.mounts.get(index) else {
                    return Ok(compact_str::CompactString::default());
                };

                match parts.get(2) {
                    Some(&"source") => Ok(mount.source.clone()),
                    Some(&"target") => Ok(mount.target.clone()),
                    Some(&"read_only") => Ok(mount.read_only.to_compact_string()),
                    _ => Self::unknown_server_variable(server, parts),
                }
            }
            "allocations" => match parts.get(1) {
                Some(&"force_outgoing_ip") => {
                    Ok(config.allocations.force_outgoing_ip.to_compact_string())
                }
                Some(&"default") => Self::lookup_default_allocation(server, &config, parts),
                _ => Self::unknown_server_variable(server, parts),
            },
            "build" => {
                let Some(subpath) = parts.get(1) else {
                    return Self::unknown_server_variable(server, parts);
                };

                match *subpath {
                    "memory" | "memory_limit" => Ok(config.build.memory_limit.to_compact_string()),
                    "overhead_memory" => Ok(config.build.overhead_memory.to_compact_string()),
                    "swap" => Ok(config.build.swap.to_compact_string()),
                    "io" | "io_weight" => Ok(config
                        .build
                        .io_weight
                        .map_or_else(|| "500".into(), |v| v.to_compact_string())),
                    "cpu" | "cpu_limit" => Ok(config.build.cpu_limit.to_compact_string()),
                    "disk" | "disk_space" => Ok(config.build.disk_space.to_compact_string()),
                    "threads" => Ok(config.build.threads.clone().unwrap_or_default()),
                    "oom_disabled" => Ok(config.build.oom_disabled.to_compact_string()),
                    "oom_killer" => Ok((!config.build.oom_disabled).to_compact_string()),
                    "image" => Ok(config.container.image.clone()),
                    "default" => Self::lookup_default_allocation(server, &config, parts),
                    "env" | "environment" => match parts.get(2) {
                        Some(env_var) => Ok(Self::lookup_environment_variable(
                            server,
                            &config.environment,
                            env_var,
                        )),
                        None => Self::unknown_server_variable(server, parts),
                    },
                    _ => Self::unknown_server_variable(server, parts),
                }
            }
            "env" | "environment" => match parts.get(1) {
                Some(env_var) => Ok(Self::lookup_environment_variable(
                    server,
                    &config.environment,
                    env_var,
                )),
                None => Self::unknown_server_variable(server, parts),
            },
            _ => Self::unknown_server_variable(server, parts),
        }
    }

    fn lookup_default_allocation(
        server: &crate::server::Server,
        config: &crate::server::configuration::ServerConfiguration,
        parts: &[&str],
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        let default = config.allocations.default.as_ref();

        match parts.get(2) {
            Some(&"ip") => Ok(default.map(|d| d.ip.clone()).unwrap_or_default()),
            Some(&"port") => Ok(default
                .map(|d| d.port.to_compact_string())
                .unwrap_or_default()),
            _ => Self::unknown_server_variable(server, parts),
        }
    }

    fn lookup_config_variable(
        server: &crate::server::Server,
        parts: &[&str],
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        if parts.is_empty() {
            return Ok(compact_str::CompactString::default());
        }

        match parts {
            ["docker", "interface"] | ["docker", "network", "interface"] => Ok(server
                .app_state
                .config
                .load()
                .docker
                .network
                .interface
                .to_compact_string()),
            _ => {
                let joined = parts.join(".");

                tracing::warn!(
                    server = %server.uuid,
                    "config variable is not readable: config.{}",
                    joined
                );

                Ok(compact_str::format_compact!("{{{{config.{}}}}}", joined))
            }
        }
    }

    async fn replace_all_placeholders(
        server: &crate::server::Server,
        input: &serde_json::Value,
    ) -> Result<compact_str::CompactString, anyhow::Error> {
        let input = match input.as_str() {
            Some(s) => s,
            None => return Self::lookup_value(server, input).await,
        };

        let mut result = compact_str::CompactString::default();
        let mut chars = input.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '{' && chars.peek() == Some(&'{') {
                chars.next();
                let mut placeholder = compact_str::CompactString::from("{{");
                let mut found_end = false;

                while let Some(ch) = chars.next() {
                    placeholder.push(ch);
                    if ch == '}' && chars.peek() == Some(&'}') {
                        chars.next();
                        placeholder.push('}');
                        found_end = true;
                        break;
                    }
                }

                if found_end {
                    let value = serde_json::Value::String(placeholder.to_string());
                    match Self::lookup_value(server, &value).await {
                        Ok(replacement) => result.push_str(&replacement),
                        Err(err) => {
                            tracing::error!(
                                server = %server.uuid,
                                "failed to lookup variable {}: {:?}",
                                placeholder,
                                err
                            );
                            result.push_str(&placeholder);
                        }
                    }
                } else {
                    result.push_str(&placeholder);
                }
            } else {
                result.push(ch);
            }
        }

        Ok(result)
    }
}

nestify::nest! {
    #[derive(ToSchema, Deserialize)]
    pub struct ProcessConfiguration {
        #[serde(default)]
        pub startup: #[derive(ToSchema, Deserialize, Clone, DefaultFromSerde)] pub struct ProcessConfigurationStartup {
            pub done: Option<Vec<compact_str::CompactString>>,
            #[serde(default)]
            pub strip_ansi: bool,
        },
        #[serde(default)]
        pub stop: #[derive(ToSchema, Deserialize, DefaultFromSerde)] pub struct ProcessConfigurationStop {
            #[serde(default)]
            pub r#type: compact_str::CompactString,
            pub value: Option<compact_str::CompactString>,
        },

        #[serde(default)]
        pub configs: Vec<ServerConfigurationFile>,
    }
}

impl ProcessConfiguration {
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            startup: ProcessConfigurationStartup::default(),
            stop: ProcessConfigurationStop::default(),
            configs: Vec::new(),
        }
    }

    pub async fn update_files(&self, server: &crate::server::Server) -> Result<(), anyhow::Error> {
        tracing::info!(
            server = %server.uuid,
            "starting configuration file updates with {} configuration files",
            self.configs.len()
        );

        if self.configs.is_empty() {
            return Ok(());
        }

        for config in self.configs.iter() {
            let file_path = server.filesystem.relative_path(Path::new(&config.file));

            if let Some(parent) = file_path.parent()
                && parent.components().next().is_some()
            {
                server
                    .filesystem
                    .async_create_chowned_dir_all(&parent, None)
                    .await?;
            }

            let mut file_content = String::new();
            if let Ok(metadata) = server.filesystem.async_metadata(&file_path).await
                && metadata.is_file()
            {
                if metadata.len() > MAX_CONFIGURATION_FILE_SIZE {
                    tracing::warn!(
                        server = %server.uuid,
                        "skipping configuration file {}, it is {} bytes which exceeds the limit of {} bytes",
                        file_path.display(),
                        metadata.len(),
                        MAX_CONFIGURATION_FILE_SIZE
                    );

                    continue;
                }

                file_content = match server
                    .filesystem
                    .async_read_to_string(&file_path, MAX_CONFIGURATION_FILE_SIZE as usize)
                    .await
                {
                    Ok(content) => content,
                    Err(err) => {
                        tracing::warn!(
                            server = %server.uuid,
                            "skipping configuration file {}, it could not be read: {:#?}",
                            file_path.display(),
                            err
                        );

                        continue;
                    }
                };
            } else if !config.create_new {
                continue;
            }

            let updated_content = match config.parser {
                ServerConfigurationFileParser::Properties => {
                    properties::PropertiesFileParser::process_file(&file_content, config, server)
                        .await?
                }
                ServerConfigurationFileParser::Json => {
                    json::JsonFileParser::process_file(&file_content, config, server).await?
                }
                ServerConfigurationFileParser::Yaml => {
                    yaml::YamlFileParser::process_file(&file_content, config, server).await?
                }
                ServerConfigurationFileParser::Ini => {
                    ini::IniFileParser::process_file(&file_content, config, server).await?
                }
                ServerConfigurationFileParser::Xml => {
                    xml::XmlFileParser::process_file(&file_content, config, server).await?
                }
                ServerConfigurationFileParser::File => {
                    plain::PlainFileParser::process_file(&file_content, config, server).await?
                }
                ServerConfigurationFileParser::Toml => {
                    toml::TomlFileParser::process_file(&file_content, config, server).await?
                }
            };

            server
                .filesystem
                .async_write(&file_path, updated_content)
                .await?;

            tracing::debug!(
                server = %server.uuid,
                "successfully processed configuration file: {}",
                file_path.display()
            );
        }

        tracing::info!(
            server = %server.uuid,
            "completed all configuration file updates"
        );

        Ok(())
    }
}

#[async_trait::async_trait]
pub trait ProcessConfigurationFileParser {
    async fn process_file(
        content: &str,
        config: &ServerConfigurationFile,
        server: &crate::server::Server,
    ) -> Result<Vec<u8>, anyhow::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::configuration::{
        Mount, ServerConfiguration, ServerConfigurationAllocationsDefault,
    };

    fn resolve_with(
        input: &str,
        setup: impl FnOnce(&mut ServerConfiguration),
    ) -> compact_str::CompactString {
        tokio_test::block_on(async {
            let state = crate::routes::AppState::mock();
            let server = crate::server::Server::mock(uuid::Uuid::new_v4(), state);

            setup(&mut *server.configuration.write().await);

            ServerConfigurationFile::replace_all_placeholders(
                &server,
                &serde_json::Value::String(input.to_string()),
            )
            .await
            .unwrap()
        })
    }

    fn resolve(input: &str) -> compact_str::CompactString {
        resolve_with(input, |_| {})
    }

    #[test]
    fn pterodactyl_build_aliases() {
        assert_eq!(resolve("{{server.build.memory}}"), "2048");
        assert_eq!(resolve("{{server.build.swap}}"), "1024");
        assert_eq!(resolve("{{server.build.io}}"), "500");
        assert_eq!(resolve("{{server.build.cpu}}"), "2");
        assert_eq!(resolve("{{server.build.disk}}"), "10240");
        assert_eq!(resolve("{{server.build.image}}"), "example/image:latest");
        assert_eq!(resolve("{{server.build.oom_disabled}}"), "false");
    }

    #[test]
    fn pelican_build_aliases() {
        assert_eq!(resolve("{{server.build.memory_limit}}"), "2048");
        assert_eq!(resolve("{{server.build.io_weight}}"), "500");
        assert_eq!(resolve("{{server.build.cpu_limit}}"), "2");
        assert_eq!(resolve("{{server.build.disk_space}}"), "10240");
        assert_eq!(resolve("{{server.build.oom_killer}}"), "true");
    }

    #[test]
    fn default_allocation_is_reachable_under_both_dialects() {
        let setup = |config: &mut ServerConfiguration| {
            config.allocations.default = Some(ServerConfigurationAllocationsDefault {
                ip: "10.0.0.4".into(),
                port: 25565,
            });
        };

        assert_eq!(
            resolve_with("{{server.build.default.ip}}", setup),
            "10.0.0.4"
        );
        assert_eq!(
            resolve_with("{{server.allocations.default.ip}}", setup),
            "10.0.0.4"
        );
        assert_eq!(
            resolve_with("{{server.allocations.default.port}}", setup),
            "25565"
        );
    }

    #[test]
    fn missing_default_allocation_resolves_empty() {
        assert_eq!(resolve("{{server.allocations.default.port}}"), "");
    }

    #[test]
    fn environment_aliases_agree() {
        let setup = |config: &mut ServerConfiguration| {
            config
                .environment
                .insert("SERVER_JARFILE".into(), serde_json::json!("server.jar"));
        };

        for path in [
            "{{env.SERVER_JARFILE}}",
            "{{environment.SERVER_JARFILE}}",
            "{{server.env.SERVER_JARFILE}}",
            "{{server.environment.SERVER_JARFILE}}",
            "{{server.build.env.SERVER_JARFILE}}",
            "{{server.build.environment.SERVER_JARFILE}}",
        ] {
            assert_eq!(resolve_with(path, setup), "server.jar", "path: {path}");
        }
    }

    #[test]
    fn server_metadata_is_reachable() {
        let uuid = uuid::Uuid::new_v4();

        assert_eq!(
            resolve_with("{{server.uuid}}", |config| config.uuid = uuid),
            uuid.to_string()
        );
        assert_eq!(resolve("{{server.meta.name}}"), "Example Server");
        assert_eq!(resolve("{{server.suspended}}"), "false");
        assert_eq!(
            resolve("{{server.container.image}}"),
            "example/image:latest"
        );
    }

    #[test]
    fn egg_id_is_reachable_under_both_dialects() {
        let uuid = uuid::Uuid::new_v4();
        let setup = |config: &mut ServerConfiguration| config.egg.id = uuid;

        assert_eq!(resolve_with("{{server.egg.id}}", setup), uuid.to_string());
        assert_eq!(
            resolve_with("{{server.service.egg}}", setup),
            uuid.to_string()
        );
    }

    #[test]
    fn labels_and_mounts_are_indexable() {
        let setup = |config: &mut ServerConfiguration| {
            config
                .labels
                .insert("com.example.tier".to_string(), "gold".to_string());
            config.mounts.push(Mount {
                default: false,
                target: "/data".into(),
                source: "/srv/data".into(),
                read_only: true,
            });
        };

        assert_eq!(
            resolve_with("{{server.labels.com.example.tier}}", setup),
            "gold"
        );
        assert_eq!(resolve_with("{{server.mounts.0.target}}", setup), "/data");
        assert_eq!(resolve_with("{{server.mounts.0.read_only}}", setup), "true");
        assert_eq!(resolve_with("{{server.mounts.3.target}}", setup), "");
    }

    #[test]
    fn unknown_server_paths_resolve_empty() {
        assert_eq!(resolve("{{server.nonsense}}"), "");
        assert_eq!(resolve("{{server.build.nonsense}}"), "");
    }

    #[test]
    fn allowed_config_variables_resolve() {
        let interface = tokio_test::block_on(async {
            crate::routes::AppState::mock()
                .config
                .load()
                .docker
                .network
                .interface
                .clone()
        });

        assert_eq!(resolve("{{config.docker.interface}}"), interface);
        assert_eq!(resolve("{{config.docker.network.interface}}"), interface);
    }

    #[test]
    fn denied_config_variables_keep_the_placeholder() {
        for path in [
            "{{config.docker}}",
            "{{config.docker.socket}}",
            "{{config.docker.registries.ghcr.username}}",
            "{{config.docker.network.name}}",
            "{{config.docker.log_config.config}}",
            "{{config.token}}",
            "{{config.docker.network.interface.extra}}",
        ] {
            assert_eq!(resolve(path), path, "path: {path}");
        }
    }

    #[test]
    fn placeholders_resolve_inside_surrounding_text() {
        assert_eq!(
            resolve("-Xmx{{server.build.memory}}M -Xms{{server.build.memory}}M"),
            "-Xmx2048M -Xms2048M"
        );
    }
}
