//! The default connection target a custom profile routes traffic to.

use serde::{Deserialize, Serialize};

/// The default connection target a profile's traffic routes to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    Outbound(String),
    Balancer { tag: String, members: Vec<String> },
}

impl Target {
    pub fn describe(&self) -> String {
        match self {
            Target::Outbound(tag) => format!("outbound {tag}"),
            Target::Balancer { tag, members } => {
                format!("balancer {tag} ({})", members.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_describe() {
        assert_eq!(
            Target::Outbound("proxy".into()).describe(),
            "outbound proxy"
        );
        assert_eq!(
            Target::Balancer {
                tag: "lb".into(),
                members: vec!["node1".into(), "node2".into()],
            }
            .describe(),
            "balancer lb (node1, node2)"
        );
    }
}
