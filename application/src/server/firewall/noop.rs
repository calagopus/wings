use super::{FirewallBackend, FirewallServerSpec};

pub struct NoopFirewall {
    enforcing: bool,
}

impl NoopFirewall {
    pub fn new(enforcing: bool) -> Self {
        Self { enforcing }
    }
}

#[async_trait::async_trait]
impl FirewallBackend for NoopFirewall {
    async fn boot(&self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn sync(&self, spec: &FirewallServerSpec) -> Result<(), anyhow::Error> {
        if spec.rules.is_empty() {
            return Ok(());
        }

        if self.enforcing {
            return Err(anyhow::anyhow!(
                "server has firewall rules configured, but no usable firewall backend is available on this host (set docker.firewall.backend to disabled to run such servers unprotected)"
            ));
        }

        tracing::warn!(
            server = %spec.server,
            "server has firewall rules configured, but the firewall backend is disabled - the rules will not be applied"
        );

        Ok(())
    }

    async fn clear(&self, _server: uuid::Uuid) -> Result<(), anyhow::Error> {
        Ok(())
    }

    async fn reconcile(&self, specs: &[FirewallServerSpec]) -> Result<(), anyhow::Error> {
        for spec in specs {
            if !spec.rules.is_empty() {
                tracing::warn!(
                    server = %spec.server,
                    "server has firewall rules configured, but no firewall backend is active - the rules will not be applied"
                );
            }
        }

        Ok(())
    }
}
