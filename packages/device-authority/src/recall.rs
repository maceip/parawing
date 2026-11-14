// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Zero-LLM structural `FormRecipe` recall store (`PARAWING_RECALL_PATH`).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::command::FormFieldCommand;
use crate::control;
use crate::observe::{ElementSnapshot, PageSnapshot};

/// Environment variable overriding the default `RecallStore` JSON path.
pub const RECALL_PATH_ENV: &str = "PARAWING_RECALL_PATH";

/// Single recorded form-control binding in a `FormRecipe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeField {
    /// Optional DOM `id` attribute of the control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_id: Option<String>,
    /// Optional DOM `name` attribute of the control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Normalized accessible label of the control.
    pub label: String,
    /// Recorded action (`"type"`, `"select"`, `"check"`, or `"fill_secret"`).
    pub action: String,
    /// Non-secret literal value (`None` whenever `action == "fill_secret"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Blind credential origin reference when `action == "fill_secret"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// Blind credential username reference when `action == "fill_secret"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// Structural form replay recipe bound to an origin and `form_signature`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormRecipe {
    /// Stable recipe identifier (`recipe_1`, `recipe_2`, ...).
    pub recipe_id: String,
    /// Normalized document origin (`scheme://host[:port]`).
    pub origin: String,
    /// Structural control hash (`sig_<16hex>`).
    pub form_signature: String,
    /// Ordered field bindings.
    pub fields: Vec<RecipeField>,
    /// ISO-8601 timestamp of last update.
    pub updated_at: String,
}

/// Persisted collection of structural `FormRecipe` entries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecallStore {
    /// Stored form recipes.
    pub recipes: Vec<FormRecipe>,
}

/// Resolves the active recall store path from `PARAWING_RECALL_PATH` or `/tmp`.
pub fn recall_path() -> PathBuf {
    std::env::var(RECALL_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/parawing-recall.json"))
}

/// Loads a `RecallStore` from an explicit filesystem `path`.
pub fn load_store_from(path: &Path) -> RecallStore {
    let Ok(raw) = fs::read_to_string(path) else {
        return RecallStore::default();
    };
    serde_json::from_str::<RecallStore>(&raw).unwrap_or_default()
}

/// Loads the `RecallStore` from `recall_path()`.
pub fn load_store() -> RecallStore {
    load_store_from(&recall_path())
}

/// Persists `store` to `path` with owner-only (`0600`) file permissions on Unix.
pub fn save_store_to(path: &Path, store: &RecallStore) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let serialized =
        serde_json::to_string_pretty(store).map_err(|e| format!("serialize recall: {e}"))?;
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| format!("open recall {}: {e}", path.display()))?;
    file.write_all(serialized.as_bytes())
        .map_err(|e| format!("write recall {}: {e}", path.display()))?;
    file.flush()
        .map_err(|e| format!("flush recall {}: {e}", path.display()))
}

/// Extracts `scheme://host[:port]` from `url_str`.
pub fn origin_of(url_str: &str) -> String {
    let Ok(parsed) = Url::parse(url_str) else {
        return url_str.to_string();
    };
    match (parsed.scheme(), parsed.host_str(), parsed.port()) {
        (scheme, Some(host), Some(port)) => format!("{scheme}://{host}:{port}"),
        (scheme, Some(host), None) => format!("{scheme}://{host}"),
        _ => url_str.to_string(),
    }
}

/// Computes a deterministic `sig_<16hex>` structural signature over form controls.
pub fn compute_form_signature(elements: &[ElementSnapshot]) -> Option<String> {
    let controls: Vec<&ElementSnapshot> = elements
        .iter()
        .filter(|e| matches!(e.tag.as_str(), "input" | "select" | "textarea"))
        .collect();
    if controls.is_empty() {
        return None;
    }
    let mut hasher = Sha256::new();
    for el in controls {
        hasher.update(el.tag.as_bytes());
        hasher.update([0]);
        hasher.update(el.input_type.as_deref().unwrap_or_default().as_bytes());
        hasher.update([0]);
        hasher.update(el.name.as_deref().unwrap_or_default().as_bytes());
        hasher.update([0]);
        hasher.update(el.dom_id.as_deref().unwrap_or_default().as_bytes());
        hasher.update([0]);
        hasher.update(el.role.as_bytes());
        hasher.update([0xff]);
    }
    let digest = format!("{:x}", hasher.finalize());
    Some(format!("sig_{}", &digest[..16]))
}

/// Searches `store` for a recipe matching `(origin, form_signature)` (exact origin preferred).
pub fn find_matching_recipe_in(
    store: &RecallStore,
    url_str: &str,
    form_signature: Option<&str>,
) -> Option<FormRecipe> {
    let sig = form_signature?;
    let orig = origin_of(url_str);
    store
        .recipes
        .iter()
        .find(|r| r.form_signature == sig && r.origin == orig)
        .or_else(|| store.recipes.iter().find(|r| r.form_signature == sig))
        .cloned()
}

/// Searches the default `RecallStore` for a recipe matching `(url_str, form_signature)`.
pub fn find_matching_recipe(url_str: &str, form_signature: Option<&str>) -> Option<FormRecipe> {
    let store = load_store();
    find_matching_recipe_in(&store, url_str, form_signature)
}

/// Looks up a stored `FormRecipe` by exact `recipe_id` inside `store`.
pub fn get_recipe_in(store: &RecallStore, recipe_id: &str) -> Option<FormRecipe> {
    store
        .recipes
        .iter()
        .find(|r| r.recipe_id == recipe_id)
        .cloned()
}

/// Looks up a stored `FormRecipe` by exact `recipe_id` in the default store.
pub fn get_recipe_by_id(recipe_id: &str) -> Option<FormRecipe> {
    get_recipe_in(&load_store(), recipe_id)
}

/// Records or updates a `FormRecipe` inside `store`, stripping values from `fill_secret` fields.
pub fn record_recipe_in(
    store: &mut RecallStore,
    url_str: &str,
    form_signature: &str,
    fields: &[FormFieldCommand],
    snapshot: &PageSnapshot,
) -> Option<FormRecipe> {
    let mut recipe_fields = Vec::new();
    for f in fields {
        let Some(el) = snapshot.elements.iter().find(|e| {
            f.target_ref.as_deref() == Some(e.node_ref.as_str())
                || f.target_id.as_deref() == Some(e.id.as_str())
        }) else {
            continue;
        };
        let value = if f.action == "fill_secret"
            || el.value_state == crate::observe::ValueState::Sensitive
        {
            None
        } else {
            f.value.clone()
        };
        recipe_fields.push(RecipeField {
            dom_id: el.dom_id.clone(),
            name: el.name.clone(),
            label: el.label.clone(),
            action: f.action.clone(),
            value,
            origin: f.origin.clone(),
            username: f.username.clone(),
        });
    }
    if recipe_fields.is_empty() {
        return None;
    }

    let orig = origin_of(url_str);
    let now = control::now_iso();
    if let Some(existing) = store
        .recipes
        .iter_mut()
        .find(|r| r.origin == orig && r.form_signature == form_signature)
    {
        existing.fields = recipe_fields;
        existing.updated_at = now;
        return Some(existing.clone());
    }

    let recipe = FormRecipe {
        recipe_id: format!("recipe_{}", store.recipes.len() + 1),
        origin: orig,
        form_signature: form_signature.to_string(),
        fields: recipe_fields,
        updated_at: now,
    };
    store.recipes.push(recipe.clone());
    Some(recipe)
}

/// Records a `FormRecipe` and persists it to `recall_path()`.
pub fn record_recipe(
    url_str: &str,
    form_signature: &str,
    fields: &[FormFieldCommand],
    snapshot: &PageSnapshot,
) {
    let path = recall_path();
    let mut store = load_store_from(&path);
    if record_recipe_in(&mut store, url_str, form_signature, fields, snapshot).is_some() {
        let _ = save_store_to(&path, &store);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observe::{Bounds, RawDomNode, ScrollSnapshot, SnapshotMetadata, build_snapshot};
    use std::collections::HashMap;

    #[test]
    fn strips_secrets_and_matches_structural_signature() {
        let mut user_attrs = HashMap::new();
        user_attrs.insert("type".into(), "email".into());
        user_attrs.insert("id".into(), "email".into());
        user_attrs.insert("name".into(), "email".into());

        let mut pw_attrs = HashMap::new();
        pw_attrs.insert("type".into(), "password".into());
        pw_attrs.insert("id".into(), "password".into());
        pw_attrs.insert("name".into(), "password".into());

        let rect = Some(Bounds {
            x: 10.0,
            y: 10.0,
            width: 180.0,
            height: 28.0,
        });
        let root = RawDomNode {
            node_id: 1,
            tag: "form".into(),
            children: vec![
                RawDomNode {
                    node_id: 2,
                    tag: "input".into(),
                    attributes: user_attrs,
                    bounds: rect,
                    ..Default::default()
                },
                RawDomNode {
                    node_id: 3,
                    tag: "input".into(),
                    attributes: pw_attrs,
                    bounds: rect,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let snap = build_snapshot(
            &root,
            None,
            ScrollSnapshot {
                x: 0.0,
                y: 0.0,
                height: 600.0,
            },
            SnapshotMetadata {
                snapshot_id: 1,
                tab_id: 1,
                page_id: 1,
                document_generation: 1,
                url: "https://app.example.com/login".into(),
                title: "Login".into(),
                viewport_width: 800.0,
                viewport_height: 600.0,
                scale: 1.0,
            },
        );
        let sig = snap.form_signature.clone().expect("form signature");
        assert!(sig.starts_with("sig_"));

        let cmds = vec![
            FormFieldCommand {
                target_id: Some("el_1".into()),
                target_ref: None,
                action: "type".into(),
                value: Some("ada@example.com".into()),
                origin: None,
                username: None,
                account_id: None,
            },
            FormFieldCommand {
                target_id: Some("el_2".into()),
                target_ref: None,
                action: "fill_secret".into(),
                value: Some("must-be-stripped".into()),
                origin: Some("https://app.example.com".into()),
                username: Some("ada@example.com".into()),
                account_id: None,
            },
        ];

        let mut store = RecallStore::default();
        let recipe = record_recipe_in(
            &mut store,
            "https://app.example.com/login",
            &sig,
            &cmds,
            &snap,
        )
        .unwrap();
        assert_eq!(recipe.fields.len(), 2);
        assert_eq!(recipe.fields[0].value.as_deref(), Some("ada@example.com"));
        assert!(recipe.fields[1].value.is_none());

        let found = find_matching_recipe_in(&store, "https://app.example.com/other", Some(&sig))
            .expect("must match recipe");
        assert_eq!(found.recipe_id, "recipe_1");
    }
}
