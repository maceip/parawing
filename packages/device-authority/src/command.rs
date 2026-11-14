// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Typed host-to-page IPC commands validated before crossing the supervision boundary.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Single field mutation within a batch `PageCommand::FillForm`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormFieldCommand {
    /// Snapshot-local target handle (`el_N`).
    pub target_id: Option<String>,
    /// Stable page-scoped node handle (`n<page_id>_<node_id>`).
    pub target_ref: Option<String>,
    /// Field operation (`"type"`, `"select"`, `"check"`, or `"fill_secret"`).
    pub action: String,
    /// Non-secret value (`None` when `action == "fill_secret"`).
    pub value: Option<String>,
    /// Vault/Keychain origin when `action == "fill_secret"`.
    pub origin: Option<String>,
    /// Vault/Keychain account identifier when `action == "fill_secret"`.
    pub username: Option<String>,
    /// Optional explicit vault account ID.
    pub account_id: Option<String>,
}

impl FormFieldCommand {
    /// Parses and validates a `FormFieldCommand` from an untyped JSON object.
    pub fn from_value(val: &Value) -> Option<Self> {
        let action = val.get("action").and_then(Value::as_str)?.to_string();
        let target_id = non_empty_str(val, "target_id");
        let target_ref = non_empty_str(val, "target_ref");
        if target_id.is_none() && target_ref.is_none() {
            return None;
        }

        let value = val.get("value").and_then(Value::as_str).map(str::to_string);
        let origin = non_empty_str(val, "origin");
        let username = non_empty_str(val, "username").or_else(|| non_empty_str(val, "vault_key"));
        let account_id = val
            .get("account_id")
            .and_then(Value::as_str)
            .map(str::to_string);

        match action.as_str() {
            "type" | "select" | "check" if value.is_some() => {}
            "fill_secret" if value.is_none() && origin.is_some() && username.is_some() => {}
            _ => return None,
        }

        Some(Self {
            target_id,
            target_ref,
            action,
            value,
            origin,
            username,
            account_id,
        })
    }

    /// Serializes the command for audit/protocol framing without exposing raw secrets.
    pub fn to_value(&self) -> Value {
        if self.action == "fill_secret" {
            json!({
                "target_id": self.target_id,
                "target_ref": self.target_ref,
                "action": "fill_secret",
                "origin": self.origin,
                "username": self.username,
                "account_id": self.account_id,
            })
        } else {
            json!({
                "target_id": self.target_id,
                "target_ref": self.target_ref,
                "action": self.action,
                "value": self.value,
            })
        }
    }
}

fn non_empty_str(val: &Value, key: &str) -> Option<String> {
    val.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Validated command dispatched by the trusted host to a page target after approval.
#[derive(Clone, Debug, PartialEq)]
pub enum PageCommand {
    /// Clicks an interactive element.
    Click {
        /// Snapshot-local handle (`el_N`).
        target_id: String,
        /// Optional stable node handle (`n<page_id>_<node_id>`).
        target_ref: Option<String>,
    },
    /// Enters non-sensitive text into a form control.
    Type {
        /// Snapshot-local handle (`el_N`).
        target_id: String,
        /// Optional stable node handle.
        target_ref: Option<String>,
        /// Text to enter.
        text: String,
    },
    /// Selects an `<option>` value on a `<select>` control.
    Select {
        /// Snapshot-local handle (`el_N`).
        target_id: String,
        /// Optional stable node handle.
        target_ref: Option<String>,
        /// Selected option value.
        value: String,
    },
    /// Populates multiple form controls atomically.
    FillForm {
        /// Validated field commands.
        fields: Vec<FormFieldCommand>,
    },
    /// Replays a stored structural `FormRecipe`.
    ReplayRecipe {
        /// Optional explicit `recipe_id` (empty matches by current `form_signature`).
        recipe_id: String,
    },
    /// Submits a form or triggers a submit button.
    Submit {
        /// Snapshot-local handle (`el_N`).
        target_id: String,
        /// Optional stable node handle.
        target_ref: Option<String>,
    },
    /// Scrolls vertically by `dy` CSS pixels (`[-10000.0, 10000.0]`).
    Scroll {
        /// Vertical scroll delta.
        dy: f64,
    },
    /// Navigates the target to `url`.
    Navigate {
        /// Destination URL.
        url: String,
    },
    /// Navigates backward in target session history.
    Back,
    /// Navigates forward in target session history.
    Forward,
    /// Reloads the current target document.
    Reload,
}

impl PageCommand {
    /// Parses a `PageCommand` from an untyped control-protocol `operation` object.
    pub fn from_operation(operation: &Value) -> Option<Self> {
        let kind = operation.get("kind").and_then(Value::as_str)?;
        let target_id = || {
            operation
                .get("target_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let target_ref = || non_empty_str(operation, "target_ref");

        match kind {
            "click" => Some(Self::Click {
                target_id: target_id(),
                target_ref: target_ref(),
            }),
            "type" => Some(Self::Type {
                target_id: target_id(),
                target_ref: target_ref(),
                text: operation
                    .get("text")
                    .or_else(|| operation.get("value"))
                    .and_then(Value::as_str)?
                    .to_string(),
            }),
            "select" => Some(Self::Select {
                target_id: target_id(),
                target_ref: target_ref(),
                value: operation.get("value").and_then(Value::as_str)?.to_string(),
            }),
            "fill_form" => parse_fill_form(operation),
            "replay_recipe" => Some(Self::ReplayRecipe {
                recipe_id: operation
                    .get("recipe_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            }),
            "submit" => Some(Self::Submit {
                target_id: target_id(),
                target_ref: target_ref(),
            }),
            "scroll" => Some(Self::Scroll {
                dy: operation
                    .get("dy")
                    .and_then(Value::as_f64)
                    .filter(|dy| dy.is_finite())?
                    .clamp(-10_000.0, 10_000.0),
            }),
            "navigate" => Some(Self::Navigate {
                url: non_empty_str(operation, "url")?,
            }),
            "back" => Some(Self::Back),
            "forward" => Some(Self::Forward),
            "reload" => Some(Self::Reload),
            _ => None,
        }
    }

    /// Returns the wire `kind` discriminator for this command.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Click { .. } => "click",
            Self::Type { .. } => "type",
            Self::Select { .. } => "select",
            Self::FillForm { .. } => "fill_form",
            Self::ReplayRecipe { .. } => "replay_recipe",
            Self::Submit { .. } => "submit",
            Self::Scroll { .. } => "scroll",
            Self::Navigate { .. } => "navigate",
            Self::Back => "back",
            Self::Forward => "forward",
            Self::Reload => "reload",
        }
    }

    /// Returns the primary snapshot-local `target_id` when present.
    pub fn target_id(&self) -> Option<&str> {
        match self {
            Self::Click { target_id, .. }
            | Self::Type { target_id, .. }
            | Self::Select { target_id, .. }
            | Self::Submit { target_id, .. }
                if !target_id.is_empty() =>
            {
                Some(target_id)
            }
            _ => None,
        }
    }

    /// Returns the primary stable `target_ref` when present.
    pub fn target_ref(&self) -> Option<&str> {
        match self {
            Self::Click { target_ref, .. }
            | Self::Type { target_ref, .. }
            | Self::Select { target_ref, .. }
            | Self::Submit { target_ref, .. } => target_ref.as_deref(),
            _ => None,
        }
    }

    /// Serializes this command into its protocol/audit JSON representation.
    pub fn to_operation(&self) -> Value {
        match self {
            Self::Click {
                target_id,
                target_ref,
            } => json!({"kind": "click", "target_id": target_id, "target_ref": target_ref}),
            Self::Type {
                target_id,
                target_ref,
                text,
            } => json!({
                "kind": "type",
                "target_id": target_id,
                "target_ref": target_ref,
                "text": text,
            }),
            Self::Select {
                target_id,
                target_ref,
                value,
            } => json!({
                "kind": "select",
                "target_id": target_id,
                "target_ref": target_ref,
                "value": value,
            }),
            Self::FillForm { fields } => json!({
                "kind": "fill_form",
                "fields": fields.iter().map(FormFieldCommand::to_value).collect::<Vec<_>>(),
            }),
            Self::ReplayRecipe { recipe_id } => json!({
                "kind": "replay_recipe",
                "recipe_id": recipe_id,
            }),
            Self::Submit {
                target_id,
                target_ref,
            } => json!({"kind": "submit", "target_id": target_id, "target_ref": target_ref}),
            Self::Scroll { dy } => json!({"kind": "scroll", "dy": dy}),
            Self::Navigate { url } => json!({"kind": "navigate", "url": url}),
            Self::Back => json!({"kind": "back"}),
            Self::Forward => json!({"kind": "forward"}),
            Self::Reload => json!({"kind": "reload"}),
        }
    }
}

fn parse_fill_form(operation: &Value) -> Option<PageCommand> {
    let arr = operation.get("fields").and_then(Value::as_array)?;
    if arr.is_empty() {
        return None;
    }
    let mut fields = Vec::with_capacity(arr.len());
    for item in arr {
        fields.push(FormFieldCommand::from_value(item)?);
    }
    Some(PageCommand::FillForm { fields })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_secret_rejects_inline_plaintext_values() {
        let bad = json!({
            "target_id": "el_2",
            "action": "fill_secret",
            "origin": "https://example.com",
            "username": "ada",
            "value": "plaintext-leak"
        });
        assert!(FormFieldCommand::from_value(&bad).is_none());

        let good = json!({
            "target_id": "el_2",
            "action": "fill_secret",
            "origin": "https://example.com",
            "username": "ada"
        });
        let cmd = FormFieldCommand::from_value(&good).expect("valid blind fill_secret");
        assert!(cmd.value.is_none());
    }

    #[test]
    fn clamps_scroll_and_rejects_nan() {
        let huge =
            PageCommand::from_operation(&json!({"kind": "scroll", "dy": 999_999.0})).unwrap();
        assert_eq!(huge, PageCommand::Scroll { dy: 10_000.0 });

        assert!(PageCommand::from_operation(&json!({"kind": "scroll", "dy": "nan"})).is_none());
    }

    #[test]
    fn round_trips_typed_commands() {
        let op = json!({
            "kind": "type",
            "target_id": "el_1",
            "target_ref": "n1_42",
            "text": "hello world"
        });
        let parsed = PageCommand::from_operation(&op).unwrap();
        assert_eq!(parsed.kind(), "type");
        assert_eq!(parsed.target_id(), Some("el_1"));
        assert_eq!(parsed.target_ref(), Some("n1_42"));
        assert_eq!(parsed.to_operation(), op);
    }
}
