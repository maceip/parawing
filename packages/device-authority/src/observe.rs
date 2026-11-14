// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Engine-agnostic DOM snapshot builder, sensitive-field classifier, and SHA-256 fingerprinting.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

/// Host-supplied document metadata for constructing a `PageSnapshot`.
#[derive(Clone, Debug, PartialEq)]
pub struct SnapshotMetadata {
    /// Monotonic snapshot counter.
    pub snapshot_id: u64,
    /// Browser tab or target numeric identifier.
    pub tab_id: u64,
    /// Page instance identifier (rotates when the top-level document object is replaced).
    pub page_id: u64,
    /// Monotonic document mutation/navigation generation counter.
    pub document_generation: u64,
    /// Trusted document URL observed by the host.
    pub url: String,
    /// Document title.
    pub title: String,
    /// Viewport width in CSS pixels.
    pub viewport_width: f32,
    /// Viewport height in CSS pixels.
    pub viewport_height: f32,
    /// Device pixel ratio / scale factor.
    pub scale: f32,
}

/// Redacted, fingerprinted page observation snapshot safe to expose over the control channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageSnapshot {
    /// Snapshot numeric identifier (`o_<snapshot_id>` on wire).
    pub snapshot_id: u64,
    /// Hosting tab or target identifier.
    pub tab_id: u64,
    /// Hosting page instance identifier.
    pub page_id: u64,
    /// Document generation counter bound into `fingerprint`.
    pub document_generation: u64,
    /// Hex SHA-256 digest binding URL, generation, and interactive element state.
    pub fingerprint: String,
    /// Document URL.
    pub url: String,
    /// Document title.
    pub title: String,
    /// Viewport geometry.
    pub viewport: ViewportSnapshot,
    /// Scroll offset and scrollable document height.
    pub scroll: ScrollSnapshot,
    /// Normalized visible document text (capped to 6,000 characters).
    pub text: String,
    /// Interactive elements visible within the current viewport.
    pub elements: Vec<ElementSnapshot>,
    /// Snapshot-local ID (`el_N`) of the currently focused element, if any.
    pub focused_element_id: Option<String>,
    /// Deterministic structural form signature (`sig_<16hex>`) when form controls exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_signature: Option<String>,
    /// Matched zero-LLM recall recipe identifier, if stored for this origin/signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_recipe_id: Option<String>,
}

/// Viewport dimensions and scale factor.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ViewportSnapshot {
    /// Width in CSS pixels.
    pub width: f32,
    /// Height in CSS pixels.
    pub height: f32,
    /// Scale factor.
    pub scale: f32,
}

/// Viewport scroll offset and total scrollable document height.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScrollSnapshot {
    /// Horizontal scroll offset in CSS pixels.
    pub x: f64,
    /// Vertical scroll offset in CSS pixels.
    pub y: f64,
    /// Total scrollable height in CSS pixels.
    pub height: f64,
}

/// `<option>` entry inside a `<select>` element snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectOptionSnapshot {
    /// Option value submitted with the form.
    pub value: String,
    /// Visible option label.
    pub label: String,
}

/// Bounding client rectangle in CSS pixels relative to the viewport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Bounds {
    /// Left coordinate.
    pub x: f64,
    /// Top coordinate.
    pub y: f64,
    /// Width.
    pub width: f64,
    /// Height.
    pub height: f64,
}

/// Redaction-aware state of an element's current value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueState {
    /// Control has an empty string value.
    Empty,
    /// Non-sensitive control has a non-empty value exposed in `ElementSnapshot::value`.
    Present,
    /// Sensitive control holds non-empty secret text; `ElementSnapshot::value` is `None`.
    Sensitive,
    /// Element does not carry a form control value.
    Unavailable,
}

/// Redacted snapshot of a single interactive DOM element.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElementSnapshot {
    /// Snapshot-local handle (`el_1`, `el_2`, ...).
    pub id: String,
    /// Optional DOM `id` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dom_id: Option<String>,
    /// Optional DOM `name` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Lowercased `<input type="...">` when `tag == "input"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    /// Page-scoped stable node handle (`n<page_id>_<node_id>`).
    pub node_ref: String,
    /// Engine-internal numeric node identifier omitted from wire JSON.
    #[serde(skip)]
    pub node_id: u64,
    /// Interaction kind (`"click"`, `"type"`, `"select"`).
    pub kind: String,
    /// ARIA or inferred semantic role.
    pub role: String,
    /// Lowercased HTML tag name.
    pub tag: String,
    /// Accessible label normalized to at most 160 characters.
    pub label: String,
    /// Client bounding box in viewport coordinates.
    pub bounds: Bounds,
    /// False when `disabled` or `aria-disabled="true"`.
    pub enabled: bool,
    /// True when intersecting the viewport with positive dimensions.
    pub visible: bool,
    /// Current value when non-sensitive (`None` whenever `value_state == Sensitive`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Value presence / redaction state.
    pub value_state: ValueState,
    /// Checkbox or radio checked state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked: Option<bool>,
    /// Option selected state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<bool>,
    /// Resolved `href` URL for links.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    /// Input `placeholder` text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    /// Available `<option>` items when `tag == "select"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<SelectOptionSnapshot>>,
}

/// Engine-neutral DOM node tree input consumed by `build_snapshot`.
#[derive(Clone, Debug, Default)]
pub struct RawDomNode {
    /// Engine-local unique node ID within the current `page_id`.
    pub node_id: u64,
    /// HTML element tag name (empty string for `#text` nodes).
    pub tag: String,
    /// Text node content when `tag.is_empty()`.
    pub text: String,
    /// Lowercased HTML attributes.
    pub attributes: HashMap<String, String>,
    /// Live input/textarea editor value when modified in the DOM.
    pub live_value: Option<String>,
    /// Live checkbox/radio checked state.
    pub live_checked: Option<bool>,
    /// Whether the engine considers this element keyboard-focusable.
    pub focussable: bool,
    /// Whether computed `cursor` is `"pointer"`.
    pub cursor_pointer: bool,
    /// Computed CSS `display` property (defaults to `"block"` / `"inline"`).
    pub display: String,
    /// Computed CSS `visibility` property (defaults to `"visible"`).
    pub visibility: String,
    /// Computed CSS `opacity` property (defaults to `"1"`).
    pub opacity: String,
    /// Client bounding box in viewport CSS pixels.
    pub bounds: Option<Bounds>,
    /// Child DOM nodes in document order.
    pub children: Vec<RawDomNode>,
}

impl RawDomNode {
    /// Looks up an attribute value by lowercase name.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    /// Concatenates descendant text content in document order.
    pub fn text_content(&self) -> String {
        if self.tag.is_empty() {
            return self.text.clone();
        }
        let mut out = String::new();
        for child in &self.children {
            let piece = child.text_content();
            if !piece.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&piece);
            }
        }
        out
    }
}

/// Normalizes whitespace runs to single spaces and truncates to `limit` Unicode scalars.
pub fn normalize_text(text: &str, limit: usize) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(limit)
        .collect()
}

/// Classifies whether a form control holds secret or payment material that must be redacted.
pub fn is_sensitive_field(
    tag: &str,
    input_type: &str,
    autocomplete: &str,
    name: &str,
    dom_id: &str,
    label: &str,
) -> bool {
    if input_type.eq_ignore_ascii_case("password") {
        return true;
    }
    let ac = autocomplete.to_ascii_lowercase();
    if ac == "one-time-code" || ac.starts_with("cc-") || ac.contains("password") {
        return true;
    }
    if !matches!(tag, "input" | "textarea" | "select") {
        return false;
    }
    let hint = format!("{name} {dom_id} {label}").to_ascii_lowercase();
    [
        "password",
        "passcode",
        "one-time code",
        "credit card",
        "card number",
        "cvv",
    ]
    .iter()
    .any(|kw| hint.contains(kw))
}

fn push_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

/// Computes the deterministic SHA-256 snapshot fingerprint binding URL, generation, and elements.
pub fn compute_fingerprint(metadata: &SnapshotMetadata, elements: &[ElementSnapshot]) -> String {
    let mut index = Sha256::new();
    for element in elements {
        push_field(&mut index, &element.id);
        push_field(&mut index, &element.role);
        push_field(&mut index, &element.label);
        push_field(
            &mut index,
            &format!(
                "{:.2},{:.2},{:.2},{:.2}",
                element.bounds.x, element.bounds.y, element.bounds.width, element.bounds.height
            ),
        );
        push_field(&mut index, &element.kind);
        push_field(&mut index, if element.enabled { "1" } else { "0" });
        push_field(&mut index, &format!("{:?}", element.checked));
        push_field(&mut index, &format!("{:?}", element.selected));
        push_field(&mut index, &format!("{:?}", element.value_state));
        if let Some(val) = &element.value {
            push_field(&mut index, val);
        }
    }
    let index_digest = index.finalize();

    let mut outer = Sha256::new();
    outer.update(metadata.url.as_bytes());
    outer.update([0]);
    outer.update(metadata.document_generation.to_string().as_bytes());
    outer.update([0]);
    outer.update(index_digest);
    format!("{:x}", outer.finalize())
}

struct FlatNode<'a> {
    node: &'a RawDomNode,
    enclosing_label: Option<(u64, String)>,
}

/// Builds a redacted, fingerprinted `PageSnapshot` from an engine-neutral `RawDomNode` tree.
pub fn build_snapshot(
    root: &RawDomNode,
    focused_node_id: Option<u64>,
    scroll: ScrollSnapshot,
    metadata: SnapshotMetadata,
) -> PageSnapshot {
    let mut labels_by_for: HashMap<String, (String, Option<Bounds>)> = HashMap::new();
    collect_for_labels(root, &mut labels_by_for);

    let mut flat = Vec::new();
    flatten_dom(root, None, &mut flat);

    let base_url = Url::parse(&metadata.url).ok();
    let mut elements = Vec::new();
    let mut max_doc_bottom: f64 = 0.0;

    for entry in &flat {
        if let Some(b) = entry.node.bounds {
            if b.width > 0.0 && b.height > 0.0 {
                max_doc_bottom = max_doc_bottom.max(b.y + scroll.y + b.height);
            }
        }
        let next_idx = elements.len() + 1;
        if let Some(snapshot) = build_element_snapshot(
            entry,
            next_idx,
            &metadata,
            base_url.as_ref(),
            &labels_by_for,
            root,
        ) {
            elements.push(snapshot);
            if elements.len() >= 512 {
                break;
            }
        }
    }

    let focused_element_id = focused_node_id.and_then(|fid| {
        elements
            .iter()
            .find(|el| el.node_id == fid)
            .map(|el| el.id.clone())
    });
    let height = scroll
        .height
        .max(max_doc_bottom)
        .max(f64::from(metadata.viewport_height));
    let fingerprint = compute_fingerprint(&metadata, &elements);
    let form_signature = crate::recall::compute_form_signature(&elements);
    let matched_recipe_id =
        crate::recall::find_matching_recipe(&metadata.url, form_signature.as_deref())
            .map(|r| r.recipe_id);

    PageSnapshot {
        snapshot_id: metadata.snapshot_id,
        tab_id: metadata.tab_id,
        page_id: metadata.page_id,
        document_generation: metadata.document_generation,
        fingerprint,
        url: metadata.url,
        title: metadata.title,
        viewport: ViewportSnapshot {
            width: metadata.viewport_width,
            height: metadata.viewport_height,
            scale: metadata.scale,
        },
        scroll: ScrollSnapshot {
            x: scroll.x,
            y: scroll.y,
            height,
        },
        text: collect_visible_text(root),
        elements,
        focused_element_id,
        form_signature,
        matched_recipe_id,
    }
}

fn collect_for_labels(node: &RawDomNode, out: &mut HashMap<String, (String, Option<Bounds>)>) {
    if node.tag.eq_ignore_ascii_case("label") {
        if let Some(target) = node.attr("for") {
            let visible_bounds = if is_node_style_hidden(node) {
                None
            } else {
                node.bounds.filter(|b| b.width > 0.0 && b.height > 0.0)
            };
            out.insert(
                target.to_string(),
                (normalize_text(&node.text_content(), 160), visible_bounds),
            );
        }
    }
    for child in &node.children {
        collect_for_labels(child, out);
    }
}

fn flatten_dom<'a>(
    node: &'a RawDomNode,
    enclosing_label: Option<(u64, String)>,
    out: &mut Vec<FlatNode<'a>>,
) {
    let tag_lc = node.tag.to_ascii_lowercase();
    if matches!(
        tag_lc.as_str(),
        "script" | "style" | "noscript" | "template"
    ) {
        return;
    }
    let next_label = if tag_lc == "label" {
        Some((node.node_id, normalize_text(&node.text_content(), 160)))
    } else {
        enclosing_label.clone()
    };
    if !tag_lc.is_empty() {
        out.push(FlatNode {
            node,
            enclosing_label,
        });
    }
    for child in &node.children {
        flatten_dom(child, next_label.clone(), out);
    }
}

fn find_node_bounds(root: &RawDomNode, target_id: u64) -> Option<Bounds> {
    if root.node_id == target_id {
        if is_node_style_hidden(root) {
            return None;
        }
        return root.bounds.filter(|b| b.width > 0.0 && b.height > 0.0);
    }
    for child in &root.children {
        if let Some(found) = find_node_bounds(child, target_id) {
            return Some(found);
        }
    }
    None
}

fn is_node_style_hidden(node: &RawDomNode) -> bool {
    node.display == "none"
        || node.visibility == "hidden"
        || node.visibility == "collapse"
        || node.opacity == "0"
}

fn is_self_hidden(node: &RawDomNode) -> bool {
    if node.attr("hidden").is_some() || node.attr("aria-hidden") == Some("true") {
        return true;
    }
    let hidden_class = node
        .attr("class")
        .unwrap_or_default()
        .split_whitespace()
        .any(|c| matches!(c, "hide" | "hidden" | "sr-only" | "invisible"));
    hidden_class || is_node_style_hidden(node)
}

fn resolve_element_bounds(
    entry: &FlatNode<'_>,
    tag: &str,
    input_type: &str,
    labels_by_for: &HashMap<String, (String, Option<Bounds>)>,
    root: &RawDomNode,
) -> Option<Bounds> {
    let checkable = tag == "input" && matches!(input_type, "radio" | "checkbox");
    let promoted = if checkable {
        promoted_checkable_bounds(entry, labels_by_for, root)
    } else {
        None
    };
    if is_self_hidden(entry.node) {
        return promoted;
    }
    entry
        .node
        .bounds
        .filter(|b| b.width > 0.0 && b.height > 0.0)
        .or(promoted)
}

fn promoted_checkable_bounds(
    entry: &FlatNode<'_>,
    labels_by_for: &HashMap<String, (String, Option<Bounds>)>,
    root: &RawDomNode,
) -> Option<Bounds> {
    if let Some(id) = entry.node.attr("id") {
        if let Some((_, Some(bounds))) = labels_by_for.get(id) {
            return Some(*bounds);
        }
    }
    let (label_node_id, _) = entry.enclosing_label.as_ref()?;
    find_node_bounds(root, *label_node_id)
}

fn build_element_snapshot(
    entry: &FlatNode<'_>,
    index: usize,
    metadata: &SnapshotMetadata,
    base_url: Option<&Url>,
    labels_by_for: &HashMap<String, (String, Option<Bounds>)>,
    root: &RawDomNode,
) -> Option<ElementSnapshot> {
    let node = entry.node;
    let tag = node.tag.to_ascii_lowercase();
    let input_type = node.attr("type").unwrap_or("text").to_ascii_lowercase();

    let classified = classify_element(&tag, &input_type, node).or_else(|| {
        node.cursor_pointer
            .then(|| ("click", "generic".to_string()))
    })?;
    let (kind, role) = classified;

    let rect = resolve_element_bounds(entry, &tag, &input_type, labels_by_for, root)?;
    let visible = rect.x < f64::from(metadata.viewport_width)
        && rect.y < f64::from(metadata.viewport_height)
        && rect.x + rect.width > 0.0
        && rect.y + rect.height > 0.0;
    if !visible {
        return None;
    }

    let label = compute_label(entry, &tag, labels_by_for);
    let sensitive = is_sensitive_field(
        &tag,
        &input_type,
        node.attr("autocomplete").unwrap_or_default(),
        node.attr("name").unwrap_or_default(),
        node.attr("id").unwrap_or_default(),
        &label,
    );
    let (value, value_state, selected) = extract_value(node, &tag, sensitive);
    let enabled = node.attr("disabled").is_none() && node.attr("aria-disabled") != Some("true");
    let href = node.attr("href").map(|raw| {
        base_url
            .and_then(|base| base.join(raw).ok())
            .map(|u| u.to_string())
            .unwrap_or_else(|| raw.to_string())
    });
    let checked = node.live_checked.or_else(|| {
        (tag == "input" && matches!(input_type.as_str(), "checkbox" | "radio"))
            .then(|| node.attr("checked").is_some())
    });

    Some(ElementSnapshot {
        id: format!("el_{index}"),
        dom_id: non_empty_attr(node, "id"),
        name: non_empty_attr(node, "name"),
        input_type: (tag == "input").then_some(input_type),
        node_ref: format!("n{}_{}", metadata.page_id, node.node_id),
        node_id: node.node_id,
        kind: kind.to_string(),
        role,
        tag: tag.clone(),
        label,
        bounds: rect,
        enabled,
        visible,
        value,
        value_state,
        checked,
        selected,
        href,
        placeholder: non_empty_attr(node, "placeholder"),
        options: (tag == "select")
            .then(|| collect_select_options(node))
            .flatten(),
    })
}

fn non_empty_attr(node: &RawDomNode, key: &str) -> Option<String> {
    node.attr(key).filter(|s| !s.is_empty()).map(str::to_string)
}

fn collect_select_options(node: &RawDomNode) -> Option<Vec<SelectOptionSnapshot>> {
    let mut opts = Vec::new();
    for child in &node.children {
        if !child.tag.eq_ignore_ascii_case("option") {
            continue;
        }
        let label = normalize_text(&child.text_content(), 120);
        let value = child
            .attr("value")
            .map(str::to_string)
            .unwrap_or_else(|| label.clone());
        opts.push(SelectOptionSnapshot { value, label });
    }
    if opts.is_empty() {
        None
    } else {
        Some(opts)
    }
}

fn classify_element(
    tag: &str,
    input_type: &str,
    node: &RawDomNode,
) -> Option<(&'static str, String)> {
    let role_attr = node.attr("role").unwrap_or_default().to_ascii_lowercase();
    let interactive_role = matches!(
        role_attr.as_str(),
        "button" | "link" | "checkbox" | "radio" | "tab" | "menuitem" | "option"
    );
    match tag {
        "a" if node.attr("href").is_some() => Some(("click", "link".into())),
        "button" => Some(("click", "button".into())),
        "textarea" => Some(("type", "textbox".into())),
        "select" => Some(("select", "combobox".into())),
        "option" => Some(("select", "option".into())),
        "label" if node.attr("for").is_some() => Some(("click", "generic".into())),
        "input" => classify_input(input_type),
        _ if interactive_role => Some(("click", role_attr)),
        _ if node.focussable => Some(("click", "generic".into())),
        _ => None,
    }
}

fn classify_input(input_type: &str) -> Option<(&'static str, String)> {
    match input_type {
        "hidden" => None,
        "checkbox" => Some(("click", "checkbox".into())),
        "radio" => Some(("click", "radio".into())),
        "submit" | "button" | "reset" | "image" | "file" => Some(("click", "button".into())),
        "search" => Some(("type", "searchbox".into())),
        _ => Some(("type", "textbox".into())),
    }
}

fn compute_label(
    entry: &FlatNode<'_>,
    tag: &str,
    labels_by_for: &HashMap<String, (String, Option<Bounds>)>,
) -> String {
    let node = entry.node;
    if let Some(aria) = node.attr("aria-label") {
        let norm = normalize_text(aria, 160);
        if !norm.is_empty() {
            return norm;
        }
    }
    if let Some(id) = node.attr("id") {
        if let Some((lbl, _)) = labels_by_for.get(id) {
            if !lbl.is_empty() {
                return lbl.clone();
            }
        }
    }
    if matches!(tag, "input" | "select" | "textarea") {
        if let Some((_, ref lbl)) = entry.enclosing_label {
            if !lbl.is_empty() {
                return lbl.clone();
            }
        }
    }
    let text = normalize_text(&node.text_content(), 160);
    if !text.is_empty() {
        return text;
    }
    for attr_name in ["placeholder", "title", "alt"] {
        if let Some(val) = node.attr(attr_name) {
            let norm = normalize_text(val, 160);
            if !norm.is_empty() {
                return norm;
            }
        }
    }
    if tag == "input" {
        if let Some(val) = node.attr("value") {
            return normalize_text(val, 160);
        }
    }
    if tag == "a" {
        if let Some(href) = node.attr("href") {
            return normalize_text(href, 160);
        }
    }
    tag.to_string()
}

fn extract_value(
    node: &RawDomNode,
    tag: &str,
    sensitive: bool,
) -> (Option<String>, ValueState, Option<bool>) {
    if sensitive {
        let present = node
            .live_value
            .as_deref()
            .map(|s| !s.is_empty())
            .or_else(|| node.attr("value").map(|v| !v.is_empty()))
            .unwrap_or(false);
        let state = if present {
            ValueState::Sensitive
        } else {
            ValueState::Empty
        };
        return (None, state, None);
    }

    let selected = (tag == "option").then(|| node.attr("selected").is_some());
    let raw_value = if let Some(live) = &node.live_value {
        Some(live.clone())
    } else if tag == "select" {
        selected_option_value(node)
    } else if tag == "textarea" {
        Some(node.text_content())
    } else if matches!(tag, "input" | "option") {
        node.attr("value").map(str::to_string)
    } else {
        None
    };

    match raw_value {
        Some(val) if !val.is_empty() => (
            Some(val.chars().take(512).collect()),
            ValueState::Present,
            selected,
        ),
        Some(_) => (Some(String::new()), ValueState::Empty, selected),
        None => (None, ValueState::Unavailable, selected),
    }
}

fn selected_option_value(node: &RawDomNode) -> Option<String> {
    for child in &node.children {
        if !child.tag.eq_ignore_ascii_case("option") || child.attr("selected").is_none() {
            continue;
        }
        return child
            .attr("value")
            .map(str::to_string)
            .or_else(|| Some(normalize_text(&child.text_content(), 512)));
    }
    None
}

fn collect_visible_text(root: &RawDomNode) -> String {
    let mut pieces = Vec::new();
    collect_text_walk(root, false, &mut pieces);
    normalize_text(&pieces.join(" "), 6000)
}

fn collect_text_walk(node: &RawDomNode, skip: bool, pieces: &mut Vec<String>) {
    let tag_lc = node.tag.to_ascii_lowercase();
    let skip_branch = skip
        || matches!(
            tag_lc.as_str(),
            "script" | "style" | "noscript" | "template"
        );
    if !skip_branch && tag_lc.is_empty() {
        let norm = normalize_text(&node.text, 6000);
        if !norm.is_empty() {
            pieces.push(norm);
        }
    }
    for child in &node.children {
        collect_text_walk(child, skip_branch, pieces);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SnapshotMetadata {
        SnapshotMetadata {
            snapshot_id: 1,
            tab_id: 10,
            page_id: 20,
            document_generation: 3,
            url: "https://login.example.com/signin".to_string(),
            title: "Sign In".to_string(),
            viewport_width: 1280.0,
            viewport_height: 800.0,
            scale: 2.0,
        }
    }

    #[test]
    fn redacts_password_and_otp_values_from_snapshots() {
        let mut pw_attrs = HashMap::new();
        pw_attrs.insert("type".into(), "password".into());
        pw_attrs.insert("id".into(), "pw".into());
        pw_attrs.insert("placeholder".into(), "Password".into());

        let mut otp_attrs = HashMap::new();
        otp_attrs.insert("type".into(), "text".into());
        otp_attrs.insert("autocomplete".into(), "one-time-code".into());
        otp_attrs.insert("aria-label".into(), "Verification Code".into());

        let root = RawDomNode {
            node_id: 1,
            tag: "form".into(),
            bounds: Some(Bounds {
                x: 0.0,
                y: 0.0,
                width: 400.0,
                height: 300.0,
            }),
            children: vec![
                RawDomNode {
                    node_id: 2,
                    tag: "input".into(),
                    attributes: pw_attrs,
                    live_value: Some("super-secret-password".into()),
                    bounds: Some(Bounds {
                        x: 10.0,
                        y: 20.0,
                        width: 200.0,
                        height: 32.0,
                    }),
                    ..Default::default()
                },
                RawDomNode {
                    node_id: 3,
                    tag: "input".into(),
                    attributes: otp_attrs,
                    live_value: Some("482910".into()),
                    bounds: Some(Bounds {
                        x: 10.0,
                        y: 70.0,
                        width: 200.0,
                        height: 32.0,
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        let snap = build_snapshot(
            &root,
            Some(2),
            ScrollSnapshot {
                x: 0.0,
                y: 0.0,
                height: 800.0,
            },
            meta(),
        );
        assert_eq!(snap.elements.len(), 2);
        assert_eq!(snap.focused_element_id.as_deref(), Some("el_1"));
        for el in &snap.elements {
            assert_eq!(el.value, None);
            assert_eq!(el.value_state, ValueState::Sensitive);
        }
        let serialized = serde_json::to_string(&snap).unwrap();
        assert!(!serialized.contains("super-secret-password"));
        assert!(!serialized.contains("482910"));
    }

    #[test]
    fn promotes_sr_only_checkbox_via_associated_label_bounds() {
        let mut input_attrs = HashMap::new();
        input_attrs.insert("type".into(), "checkbox".into());
        input_attrs.insert("id".into(), "remember".into());
        input_attrs.insert("class".into(), "sr-only".into());

        let mut label_attrs = HashMap::new();
        label_attrs.insert("for".into(), "remember".into());

        let root = RawDomNode {
            node_id: 1,
            tag: "div".into(),
            children: vec![
                RawDomNode {
                    node_id: 2,
                    tag: "input".into(),
                    attributes: input_attrs,
                    bounds: None,
                    ..Default::default()
                },
                RawDomNode {
                    node_id: 3,
                    tag: "label".into(),
                    attributes: label_attrs,
                    bounds: Some(Bounds {
                        x: 16.0,
                        y: 40.0,
                        width: 140.0,
                        height: 24.0,
                    }),
                    children: vec![RawDomNode {
                        node_id: 4,
                        text: "Remember device".into(),
                        ..Default::default()
                    }],
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
                height: 800.0,
            },
            meta(),
        );
        let checkbox = snap
            .elements
            .iter()
            .find(|e| e.role == "checkbox")
            .expect("sr-only checkbox must be promoted via its visible label");
        assert_eq!(checkbox.label, "Remember device");
        assert_eq!(checkbox.bounds.width, 140.0);
    }

    #[test]
    fn fingerprint_changes_when_generation_or_element_state_mutates() {
        let mut attrs = HashMap::new();
        attrs.insert("type".into(), "text".into());
        let mut root = RawDomNode {
            node_id: 10,
            tag: "input".into(),
            attributes: attrs,
            live_value: Some("alice".into()),
            bounds: Some(Bounds {
                x: 5.0,
                y: 5.0,
                width: 100.0,
                height: 24.0,
            }),
            ..Default::default()
        };
        let scroll = ScrollSnapshot {
            x: 0.0,
            y: 0.0,
            height: 800.0,
        };
        let s1 = build_snapshot(&root, None, scroll, meta());
        root.live_value = Some("bob".into());
        let s2 = build_snapshot(&root, None, scroll, meta());
        assert_ne!(s1.fingerprint, s2.fingerprint);

        let mut m3 = meta();
        m3.document_generation += 1;
        let s3 = build_snapshot(&root, None, scroll, m3);
        assert_ne!(s2.fingerprint, s3.fingerprint);
    }
}
