use super::{CliContext, SshCliCommand};
use serde_json::json;

pub struct PermissionsCommand;

#[async_trait::async_trait]
impl SshCliCommand for PermissionsCommand {
    fn name(&self) -> &'static str {
        "permissions"
    }

    fn about(&self) -> &'static str {
        "Show your permissions on this server"
    }

    fn usage(&self) -> Option<&'static str> {
        Some("[--json]")
    }

    async fn execute(&self, ctx: &CliContext<'_>, args: &[&str], out: &mut Vec<String>) -> bool {
        let json = match args {
            [] => false,
            ["--json"] => true,
            _ => {
                out.push(ctx.usage_line(self));
                return false;
            }
        };

        let permissions = &ctx.server.user_permissions;
        let mut list = permissions
            .permissions(ctx.user_uuid)
            .unwrap_or_default()
            .into_iter()
            .map(|permission| permission.to_str())
            .collect::<Vec<_>>();
        list.sort_unstable();
        let restricted_files = permissions.has_ignored_files(ctx.user_uuid);

        if json {
            out.push(
                json!({
                    "user": ctx.user_uuid,
                    "permissions": list,
                    "restricted_files": restricted_files,
                })
                .to_string(),
            );
        } else {
            out.push(format!("User: {}", ctx.user_uuid));
            out.push("Permissions:".into());
            for permission in list {
                out.push(format!("  {permission}"));
            }
            if restricted_files {
                out.push("Some files are hidden from you on this server.".into());
            }
        }

        true
    }
}
