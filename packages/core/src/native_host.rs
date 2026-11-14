// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! Native Rust Blitz host wrapper using std and primitive types across crate boundaries.

use ::style::properties::generated::longhands::position::computed_value::T as Position;
use ::style::properties::generated::longhands::visibility::computed_value::T as StyloVisibility;
use ::style::values::specified::box_::{DisplayInside, DisplayOutside};
use ::style::values::specified::ui::CursorKind;
use blitz_dom::node::SpecialElementData;
use blitz_dom::{local_name, BaseDocument, Node, NodeData};
use blitz_traits::NodeId;

use crate::layout::geometry::bounding_rect_for_node;
use crate::{DomHandle, NodeHandleMap};

/// Native snapshot of one DOM node with computed geometry and live control state.
#[derive(Clone, Debug)]
pub struct NativeDomNode {
    pub node_id: u32,
    pub tag: String,
    pub text: Option<String>,
    pub attributes: Vec<(String, String)>,
    pub live_value: Option<String>,
    pub live_checked: Option<bool>,
    pub focussable: bool,
    pub cursor_pointer: bool,
    pub display: String,
    pub visibility: String,
    pub opacity: String,
    pub bounds: Option<[f64; 4]>,
    pub children: Vec<NativeDomNode>,
}

/// Native snapshot of the full document tree, viewport, and scroll geometry.
#[derive(Clone, Debug)]
pub struct NativeDomSnapshot {
    pub title: String,
    pub base_url: String,
    pub viewport: (u32, u32),
    pub scroll: (f64, f64),
    pub scroll_height: f64,
    pub root: Option<NativeDomNode>,
}

/// Result of activating an interactive element in `NativeBlitzDocument`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeClickOutcome {
    Focused,
    Navigate(String),
    ToggledCheckbox(bool),
    SelectedRadio,
    SubmitForm(Option<u32>),
}

/// Extracted form submission metadata and live control values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeFormSubmission {
    pub form_node_id: Option<u32>,
    pub action: String,
    pub method: String,
    pub fields: Vec<(String, String)>,
}

/// Native host handle owning one Blitz document, Stylo styles, Taffy layout, and vello_cpu paint.
pub struct NativeBlitzDocument {
    inner: DomHandle,
}

impl NativeBlitzDocument {
    /// Parse HTML with initial viewport and resolve initial style/layout.
    pub fn from_html(
        html: &str,
        base_url: &str,
        viewport_width: u32,
        viewport_height: u32,
    ) -> Self {
        let inner = DomHandle::new(html, base_url);
        inner.set_viewport(viewport_width.max(1), viewport_height.max(1));
        inner.resolve_layout();
        Self { inner }
    }

    pub fn set_viewport(&mut self, width: u32, height: u32) {
        self.inner.set_viewport(width.max(1), height.max(1));
    }

    pub fn viewport(&self) -> (u32, u32) {
        let Ok(doc) = self.inner.doc.try_borrow() else {
            return (0, 0);
        };
        let size = doc.as_ref().viewport().window_size;
        drop(doc);
        size
    }

    pub fn set_page_scroll(&mut self, x: f64, y: f64) {
        self.inner.set_page_scroll(x, y);
    }

    pub fn page_scroll(&self) -> (f64, f64) {
        let scroll = self.inner.page_scroll.get();
        (f64::from(scroll.x), f64::from(scroll.y))
    }

    pub fn scroll_node_by(&mut self, node_id: u32, dx: f64, dy: f64) -> bool {
        self.inner.scroll_node_by(node_id, dx, dy)
    }

    pub fn set_node_scroll_offset(&mut self, node_id: u32, x: f64, y: f64) -> Option<(f64, f64)> {
        self.inner.resolve_layout();
        let Ok(doc) = self.inner.doc.try_borrow() else {
            return None;
        };
        let resolved = self.inner.resolve_node_id(node_id);
        let top_before = resolved.and_then(|nid| doc.get_node(nid)).map(|_| ());
        drop(doc);
        top_before?;
        let offset = self.inner.write_scroll_offset(node_id, x, y)?;
        let _ = offset.y;
        let info = self.inner.read_scroll_info(node_id)?;
        let y_out = offset.y;
        let _ = info;
        Some((x.max(0.0), y_out))
    }

    pub fn resolve_layout(&mut self) {
        self.inner.resolve_layout();
    }

    pub fn prepare_for_paint(&mut self, width: u32, height: u32) -> u32 {
        self.inner.prepare_for_paint(width.max(1), height.max(1))
    }

    pub fn layout_epoch(&self) -> u32 {
        self.inner.layout_epoch()
    }

    pub fn title(&self) -> String {
        self.inner.title()
    }

    pub fn base_url(&self) -> String {
        self.inner.base_url()
    }

    pub fn node_count(&self) -> usize {
        self.inner.node_count()
    }

    pub fn document_node_id(&self) -> u32 {
        self.inner.document_node_id()
    }

    pub fn get_element_by_id(&self, id: &str) -> i32 {
        self.inner.get_element_by_id(id)
    }

    pub fn query_selector(&self, selector: &str) -> Result<i32, String> {
        self.inner.query_selector_native(selector)
    }

    pub fn query_selector_all(&self, selector: &str) -> Result<Vec<i32>, String> {
        self.inner.query_selector_all_native(selector)
    }

    pub fn outer_html(&self, node_id: u32) -> String {
        self.inner.outer_html(node_id)
    }

    pub fn inner_html(&self, node_id: u32) -> String {
        self.inner.inner_html(node_id)
    }

    pub fn text_content(&self, node_id: u32) -> String {
        self.inner.text_content(node_id)
    }

    pub fn apply_ops_json(&mut self, json: &str) -> Result<u32, String> {
        self.inner.apply_ops_native(json)
    }

    pub fn set_attribute(&mut self, node_id: u32, name: &str, value: &str) -> bool {
        self.inner.set_attribute(node_id, name, value)
    }

    pub fn remove_attribute(&mut self, node_id: u32, name: &str) -> bool {
        self.inner.remove_attribute(node_id, name)
    }

    pub fn set_node_text(&mut self, node_id: u32, text: &str) -> bool {
        self.inner.set_node_text(node_id, text)
    }

    pub fn set_input_text(&mut self, node_id: u32, value: &str) -> bool {
        self.inner.set_input_text(node_id, value)
    }

    pub fn set_checkbox_checked(&mut self, node_id: u32, checked: bool) -> bool {
        self.inner.set_checkbox_checked(node_id, checked)
    }

    pub fn set_focus(&mut self, node_id: u32) -> bool {
        self.inner.set_focus(node_id)
    }

    pub fn get_focused_node_id(&self) -> i32 {
        self.inner.get_focused_node_id()
    }

    pub fn element_from_point(&mut self, x: f32, y: f32) -> i32 {
        self.inner.element_from_point(x, y)
    }

    pub fn caret_from_point(&mut self, x: f32, y: f32) -> Option<(u32, usize)> {
        self.inner.caret_from_point_native(x, y)
    }

    pub fn paint_rgba(&mut self) -> Result<Vec<u8>, String> {
        self.inner.resolve_until_images_settle();
        let scroll = self.inner.page_scroll.get();
        let scroll_u = (scroll.x.max(0.0) as u32, scroll.y.max(0.0) as u32);
        let mut doc = self
            .inner
            .doc
            .try_borrow_mut()
            .map_err(|_| "document is mutably borrowed".to_string())?;
        let (width, height) = doc.as_ref().viewport().window_size;
        let rgba = crate::paint::screenshot::paint_document_rgba_scrolled(
            doc.as_mut(),
            width,
            height,
            scroll_u,
            false,
        );
        drop(doc);
        Ok(rgba)
    }

    pub fn paint_png(&mut self) -> Result<Vec<u8>, String> {
        self.inner.resolve_until_images_settle();
        let scroll = self.inner.page_scroll.get();
        let scroll_u = (scroll.x.max(0.0) as u32, scroll.y.max(0.0) as u32);
        let mut doc = self
            .inner
            .doc
            .try_borrow_mut()
            .map_err(|_| "document is mutably borrowed".to_string())?;
        let (width, height) = doc.as_ref().viewport().window_size;
        let png = crate::paint::screenshot::paint_document_to_image_scrolled(
            doc.as_mut(),
            width,
            height,
            crate::paint::screenshot::ImageFormat::Png,
            100,
            scroll_u,
            false,
        );
        drop(doc);
        png
    }

    pub fn record_ksc0(&mut self, scroll_x: i32, scroll_y: i32) -> Vec<u8> {
        self.inner
            .render_scene(scroll_x, scroll_y, 0, 0, false, false)
    }

    pub fn render_ksc2(
        &mut self,
        acked_scroll_seq: u32,
        acked_input_seq: u32,
        known_hashes_le: &[u8],
    ) -> Vec<u8> {
        self.inner.resolve_until_images_settle();
        self.inner
            .render_scene_v2(acked_scroll_seq, acked_input_seq, known_hashes_le)
    }

    pub fn render_ksc2_with_interest(
        &mut self,
        acked_scroll_seq: u32,
        acked_input_seq: u32,
        known_hashes_le: &[u8],
        vel_x: f32,
        vel_y: f32,
        handler_regions_json: &str,
    ) -> Vec<u8> {
        self.inner.resolve_until_images_settle();
        self.inner.render_scene_v2_with_interest(
            acked_scroll_seq,
            acked_input_seq,
            known_hashes_le,
            vel_x,
            vel_y,
            handler_regions_json,
        )
    }

    /// Returns whether `ancestor_id` is an inclusive DOM ancestor of `node_id`.
    pub fn is_inclusive_ancestor(&self, ancestor_id: u32, node_id: u32) -> bool {
        self.inner.is_inclusive_ancestor(ancestor_id, node_id)
    }

    /// Reads the live value of a form control (`<input>`, `<textarea>`, or `<select>`).
    pub fn get_input_value(&self, node_id: u32) -> Option<String> {
        let nid = self.inner.resolve_node_id(node_id)?;
        let doc = self.inner.doc.borrow();
        let node = doc.get_node(nid)?;
        let val = read_node_live_value(&doc, node);
        drop(doc);
        val
    }

    /// Returns checkbox/radio checkedness for an `<input>` node.
    pub fn is_checkbox_or_radio_checked(&self, node_id: u32) -> Option<bool> {
        let nid = self.inner.resolve_node_id(node_id)?;
        let doc = self.inner.doc.borrow();
        let node = doc.get_node(nid)?;
        let checked = read_node_checked(node);
        drop(doc);
        checked
    }

    /// Captures full DOM tree, computed styles/visibility, bounds, and scroll state.
    pub fn capture_dom_snapshot(&mut self) -> NativeDomSnapshot {
        self.inner.ensure_layout();
        let title = self.title();
        let base_url = self.base_url();
        let viewport = self.viewport();
        let scroll = self.page_scroll();
        let doc = self.inner.doc.borrow();
        let mut handles = self.inner.node_handles.borrow_mut();
        let scroll_height = root_scroll_height(&doc, viewport.1 as f64);
        let root_id = doc.root_node().id;
        let root = build_native_dom_node(&doc, root_id, scroll, &mut handles);
        drop(handles);
        drop(doc);
        NativeDomSnapshot {
            title,
            base_url,
            viewport,
            scroll,
            scroll_height,
            root,
        }
    }

    /// Selects an `<option>` by `value` or visible text inside a `<select>` element.
    pub fn select_option(&mut self, node_id: u32, value_or_label: &str) -> Result<String, String> {
        let select_nid = self
            .inner
            .resolve_node_id(node_id)
            .ok_or_else(|| format!("select node {node_id} not found"))?;
        let mut doc = self.inner.doc.borrow_mut();
        let Some(node) = doc.get_node(select_nid) else {
            drop(doc);
            return Err(format!("select node {node_id} missing"));
        };
        if node.element_data().map(|e| &*e.name.local) != Some("select") {
            drop(doc);
            return Err(format!("node {node_id} is not a <select>"));
        }
        let options = collect_select_option_ids(&doc, select_nid);
        let chosen_id = find_matching_option(&doc, &options, value_or_label)
            .ok_or_else(|| format!("option '{value_or_label}' not found in <select> {node_id}"));
        let chosen_id = match chosen_id {
            Ok(id) => id,
            Err(err) => {
                drop(doc);
                return Err(err);
            }
        };
        let chosen_val = option_effective_value(&doc, chosen_id);
        {
            let mut mutr = doc.mutate();
            for opt_id in options {
                if opt_id == chosen_id {
                    mutr.set_attribute(opt_id, blitz_dom::qual_name!("selected"), "");
                } else {
                    mutr.clear_attribute(opt_id, blitz_dom::qual_name!("selected"));
                }
            }
            mutr.sync_select_label_from_attrs(select_nid);
        }
        drop(doc);
        self.inner.layout_dirty.set(true);
        Ok(chosen_val)
    }

    /// Dispatches a native click activation on `node_id` (focus, toggle, link, or submit).
    pub fn click_element(&mut self, node_id: u32) -> Result<NativeClickOutcome, String> {
        let nid = self
            .inner
            .resolve_node_id(node_id)
            .ok_or_else(|| format!("node {node_id} not found"))?;
        let (resolved_ext_id, outcome) = {
            let doc = self.inner.doc.borrow();
            let mut handles = self.inner.node_handles.borrow_mut();
            let res = resolve_click_target(&doc, nid, &mut handles);
            drop(handles);
            drop(doc);
            res?
        };
        match outcome {
            NativeClickOutcome::Navigate(href) => Ok(NativeClickOutcome::Navigate(href)),
            NativeClickOutcome::ToggledCheckbox(next) => {
                self.set_checkbox_checked(resolved_ext_id, next);
                self.set_focus(resolved_ext_id);
                Ok(NativeClickOutcome::ToggledCheckbox(next))
            }
            NativeClickOutcome::SelectedRadio => {
                self.select_radio_element(resolved_ext_id);
                self.set_focus(resolved_ext_id);
                Ok(NativeClickOutcome::SelectedRadio)
            }
            NativeClickOutcome::SubmitForm(trigger) => {
                self.set_focus(resolved_ext_id);
                Ok(NativeClickOutcome::SubmitForm(trigger))
            }
            NativeClickOutcome::Focused => {
                self.set_focus(resolved_ext_id);
                Ok(NativeClickOutcome::Focused)
            }
        }
    }

    fn select_radio_element(&mut self, ext_id: u32) {
        let Some(nid) = self.inner.resolve_node_id(ext_id) else {
            return;
        };
        let siblings = {
            let doc = self.inner.doc.borrow();
            let Some(node) = doc.get_node(nid) else {
                drop(doc);
                return;
            };
            let name = node
                .element_data()
                .and_then(|e| e.attr(local_name!("name")))
                .map(str::to_string);
            let form_id = find_associated_form(&doc, nid);
            let list = collect_matching_radios(&doc, nid, name.as_deref(), form_id);
            drop(doc);
            list
        };
        for other in siblings {
            let other_ext = self.inner.external_node_id(other);
            self.set_checkbox_checked(other_ext, other == nid);
        }
        self.set_checkbox_checked(ext_id, true);
    }

    /// Inspects `<form>` target action, method, and live name/value pairs for submission.
    pub fn inspect_form_submission(
        &mut self,
        trigger_node_id: Option<u32>,
    ) -> Result<NativeFormSubmission, String> {
        self.inner.ensure_layout();
        let fallback_focus = self.get_focused_node_id();
        let trigger_hint =
            trigger_node_id.or_else(|| (fallback_focus > 0).then_some(fallback_focus as u32));
        let doc = self.inner.doc.borrow();
        let mut handles = self.inner.node_handles.borrow_mut();
        let trigger_nid = trigger_hint.and_then(|id| handles.resolve(id));
        let form_nid = trigger_nid
            .and_then(|nid| find_associated_form(&doc, nid))
            .or_else(|| first_form_id(&doc))
            .ok_or_else(|| "no <form> element in document".to_string());
        let form_nid = match form_nid {
            Ok(id) => id,
            Err(err) => {
                drop(handles);
                drop(doc);
                return Err(err);
            }
        };
        let form_node_id = Some(handles.external_for(form_nid));
        let form_elem = doc.get_node(form_nid).and_then(|n| n.element_data());
        let action = form_elem
            .and_then(|e| e.attr(local_name!("action")))
            .unwrap_or("")
            .to_string();
        let method = form_elem
            .and_then(|e| e.attr(local_name!("method")))
            .unwrap_or("get")
            .trim()
            .to_ascii_lowercase();
        let fields = collect_form_fields(&doc, form_nid, trigger_nid);
        drop(handles);
        drop(doc);
        Ok(NativeFormSubmission {
            form_node_id,
            action,
            method: if method.is_empty() {
                "get".to_string()
            } else {
                method
            },
            fields,
        })
    }
}

fn root_scroll_height(doc: &blitz_html::HtmlDocument, viewport_h: f64) -> f64 {
    let root = doc.root_element();
    let mut bottom = viewport_h.max(0.0);
    for &cid in &root.children {
        if let Some(child) = doc.get_node(cid) {
            if child
                .element_data()
                .is_some_and(|e| e.name.local == local_name!("body"))
                && !is_fixed_position(child)
            {
                let lay = child.final_layout();
                let b = (lay.location.y + lay.size.height + lay.scroll_height()) as f64;
                bottom = bottom.max(b);
            }
        }
    }
    let layout_children = root.layout_children.borrow();
    let hoisted_children = root.hoisted_children.borrow();
    for &cid in layout_children
        .iter()
        .flatten()
        .chain(hoisted_children.iter())
    {
        if let Some(child) = doc.get_node(cid) {
            if !is_fixed_position(child) {
                let lay = child.final_layout();
                let b = (lay.location.y + lay.size.height + lay.scroll_height()) as f64;
                bottom = bottom.max(b);
            }
        }
    }
    drop(hoisted_children);
    drop(layout_children);
    bottom
}

fn is_fixed_position(node: &Node) -> bool {
    node.primary_styles()
        .is_some_and(|styles| styles.clone_position() == Position::Fixed)
}

fn read_node_checked(node: &Node) -> Option<bool> {
    let elem = node.element_data()?;
    if &*elem.name.local != "input" {
        return None;
    }
    if let SpecialElementData::CheckboxInput(b) = elem.special_data {
        return Some(b);
    }
    let ty = elem
        .attr(local_name!("type"))
        .unwrap_or("text")
        .to_ascii_lowercase();
    if ty == "checkbox" || ty == "radio" {
        return Some(elem.attr(local_name!("checked")).is_some());
    }
    None
}

fn read_node_live_value(doc: &BaseDocument, node: &Node) -> Option<String> {
    let elem = node.element_data()?;
    if let SpecialElementData::TextInput(data) = &elem.special_data {
        let val = data
            .value_override
            .clone()
            .or_else(|| {
                if &*elem.name.local == "textarea" {
                    Some(node.text_content())
                } else {
                    elem.attr(local_name!("value")).map(str::to_string)
                }
            })
            .unwrap_or_default();
        return Some(val);
    }
    if let SpecialElementData::RangeInput(v) = elem.special_data {
        return Some(v.to_string());
    }
    match &*elem.name.local {
        "select" => selected_select_value(doc, node.id),
        "textarea" => Some(node.text_content()),
        "input" => elem.attr(local_name!("value")).map(str::to_string),
        _ => None,
    }
}

fn collect_select_option_ids(doc: &BaseDocument, select_id: NodeId) -> Vec<NodeId> {
    let mut out = Vec::new();
    let Some(select_node) = doc.get_node(select_id) else {
        return out;
    };
    for &cid in &select_node.children {
        collect_options_from_child(doc, cid, &mut out);
    }
    out
}

fn collect_options_from_child(doc: &BaseDocument, cid: NodeId, out: &mut Vec<NodeId>) {
    let Some(node) = doc.get_node(cid) else {
        return;
    };
    let Some(elem) = node.element_data() else {
        return;
    };
    if &*elem.name.local == "option" {
        out.push(cid);
    } else if &*elem.name.local == "optgroup" {
        for &sub in &node.children {
            collect_options_from_child(doc, sub, out);
        }
    }
}

fn option_effective_value(doc: &BaseDocument, opt_id: NodeId) -> String {
    let Some(node) = doc.get_node(opt_id) else {
        return String::new();
    };
    node.element_data()
        .and_then(|e| e.attr(local_name!("value")))
        .map(str::to_string)
        .unwrap_or_else(|| node.text_content().trim().to_string())
}

fn find_matching_option(
    doc: &BaseDocument,
    options: &[NodeId],
    value_or_label: &str,
) -> Option<NodeId> {
    for &opt_id in options {
        let Some(node) = doc.get_node(opt_id) else {
            continue;
        };
        if let Some(val) = node
            .element_data()
            .and_then(|e| e.attr(local_name!("value")))
        {
            if val == value_or_label {
                return Some(opt_id);
            }
        }
    }
    for &opt_id in options {
        if let Some(node) = doc.get_node(opt_id) {
            if node.text_content().trim() == value_or_label {
                return Some(opt_id);
            }
        }
    }
    None
}

fn selected_select_value(doc: &BaseDocument, select_id: NodeId) -> Option<String> {
    let select_elem = doc.get_node(select_id)?.element_data()?;
    let multiple = select_elem.attr(local_name!("multiple")).is_some();
    let options = collect_select_option_ids(doc, select_id);
    let mut chosen = None;
    let mut first_enabled = None;
    for opt_id in options {
        let Some(opt_elem) = doc.get_node(opt_id).and_then(|o| o.element_data()) else {
            continue;
        };
        if opt_elem.attr(local_name!("disabled")).is_none() && first_enabled.is_none() {
            first_enabled = Some(opt_id);
        }
        if opt_elem.attr(local_name!("selected")).is_some() && (!multiple || chosen.is_none()) {
            chosen = Some(opt_id);
        }
    }
    chosen
        .or(if multiple { None } else { first_enabled })
        .map(|id| option_effective_value(doc, id))
}

fn element_style_summary(node: &Node) -> (bool, String, String, String) {
    let mut cursor_pointer = node
        .element_data()
        .is_some_and(|e| e.name.local == local_name!("a") && e.attr(local_name!("href")).is_some());
    let mut display = "block".to_string();
    let mut visibility = "visible".to_string();
    let mut opacity = "1".to_string();
    let Some(styles) = node.primary_styles() else {
        return (cursor_pointer, display, visibility, opacity);
    };
    if styles.clone_cursor().keyword == CursorKind::Pointer {
        cursor_pointer = true;
    }
    let d = styles.clone_display();
    if d.outside() == DisplayOutside::None && d.inside() == DisplayInside::None {
        display = "none".to_string();
    } else if d.outside() == DisplayOutside::Inline {
        display = "inline".to_string();
    }
    if styles.get_inherited_box().visibility != StyloVisibility::Visible {
        visibility = "hidden".to_string();
    }
    opacity = format!("{}", styles.get_effects().opacity);
    (cursor_pointer, display, visibility, opacity)
}

fn build_native_dom_node(
    doc: &blitz_html::HtmlDocument,
    node_id: NodeId,
    scroll: (f64, f64),
    handles: &mut NodeHandleMap,
) -> Option<NativeDomNode> {
    let node = doc.get_node(node_id)?;
    let ext_id = handles.external_for(node_id);
    match &node.data {
        NodeData::Comment { .. } => None,
        NodeData::Text(data) => Some(NativeDomNode {
            node_id: ext_id,
            tag: String::new(),
            text: Some(data.content.clone()),
            attributes: Vec::new(),
            live_value: None,
            live_checked: None,
            focussable: false,
            cursor_pointer: false,
            display: "inline".to_string(),
            visibility: "visible".to_string(),
            opacity: "1".to_string(),
            bounds: None,
            children: Vec::new(),
        }),
        NodeData::Document(_) | NodeData::ShadowRoot(_) => {
            let children = collect_dom_children(doc, node, false, scroll, handles);
            Some(NativeDomNode {
                node_id: ext_id,
                tag: "#document".to_string(),
                text: None,
                attributes: Vec::new(),
                live_value: None,
                live_checked: None,
                focussable: false,
                cursor_pointer: false,
                display: "block".to_string(),
                visibility: "visible".to_string(),
                opacity: "1".to_string(),
                bounds: None,
                children,
            })
        }
        NodeData::Element(elem) | NodeData::AnonymousBlock(elem) => {
            let tag = elem.name.local.to_string().to_ascii_lowercase();
            let attributes = elem
                .attrs
                .iter()
                .map(|a| (a.name.local.to_string(), a.value.clone()))
                .collect();
            let live_value = read_node_live_value(doc.as_ref(), node);
            let live_checked = read_node_checked(node);
            let (cursor_pointer, display, visibility, opacity) = element_style_summary(node);
            let rect = bounding_rect_for_node(doc, node);
            let bounds = (rect.width >= 0.0 && rect.height >= 0.0).then_some([
                rect.x as f64 - scroll.0,
                rect.y as f64 - scroll.1,
                rect.width as f64,
                rect.height as f64,
            ]);
            let is_select = tag == "select";
            let children = collect_dom_children(doc, node, is_select, scroll, handles);
            Some(NativeDomNode {
                node_id: ext_id,
                tag,
                text: None,
                attributes,
                live_value,
                live_checked,
                focussable: node.is_focussable(),
                cursor_pointer,
                display,
                visibility,
                opacity,
                bounds,
                children,
            })
        }
    }
}

fn collect_dom_children(
    doc: &blitz_html::HtmlDocument,
    node: &Node,
    skip_direct_text: bool,
    scroll: (f64, f64),
    handles: &mut NodeHandleMap,
) -> Vec<NativeDomNode> {
    let mut children = Vec::with_capacity(node.children.len());
    for &cid in &node.children {
        let Some(child) = doc.get_node(cid) else {
            continue;
        };
        if skip_direct_text && child.is_text_node() {
            continue;
        }
        if let Some(built) = build_native_dom_node(doc, cid, scroll, handles) {
            children.push(built);
        }
    }
    children
}

fn resolve_click_target(
    doc: &BaseDocument,
    nid: NodeId,
    handles: &mut NodeHandleMap,
) -> Result<(u32, NativeClickOutcome), String> {
    let mut target_nid = nid;
    let node = doc
        .get_node(target_nid)
        .ok_or_else(|| "node missing".to_string())?;
    if let Some(for_id) = node
        .element_data()
        .filter(|e| &*e.name.local == "label")
        .and_then(|e| e.attr(local_name!("for")))
    {
        if let Some(ctrl) = doc.get_element_by_id(for_id) {
            target_nid = ctrl;
        }
    }
    let ext_id = handles.external_for(target_nid);
    if let Some(href) = nearest_link_href(doc, target_nid) {
        return Ok((ext_id, NativeClickOutcome::Navigate(href)));
    }
    let target = doc
        .get_node(target_nid)
        .ok_or_else(|| "target node missing".to_string())?;
    let outcome = classify_element_click(doc, target, ext_id);
    Ok((ext_id, outcome))
}

fn nearest_link_href(doc: &BaseDocument, start: NodeId) -> Option<String> {
    let mut cur = Some(start);
    for _ in 0..32 {
        let id = cur?;
        let node = doc.get_node(id)?;
        if let Some(href) = node
            .element_data()
            .filter(|e| e.name.local == local_name!("a"))
            .and_then(|e| e.attr(local_name!("href")))
        {
            return Some(href.to_string());
        }
        cur = node.parent;
    }
    None
}

fn classify_element_click(doc: &BaseDocument, target: &Node, ext_id: u32) -> NativeClickOutcome {
    let Some(elem) = target.element_data() else {
        return NativeClickOutcome::Focused;
    };
    let tag = &*elem.name.local;
    if tag == "input" {
        let ty = elem
            .attr(local_name!("type"))
            .unwrap_or("text")
            .to_ascii_lowercase();
        if ty == "checkbox" {
            let cur = read_node_checked(target).unwrap_or(false);
            return NativeClickOutcome::ToggledCheckbox(!cur);
        }
        if ty == "radio" {
            return NativeClickOutcome::SelectedRadio;
        }
        if ty == "submit" && find_associated_form(doc, target.id).is_some() {
            return NativeClickOutcome::SubmitForm(Some(ext_id));
        }
        return NativeClickOutcome::Focused;
    }
    if tag == "button" {
        let ty = elem
            .attr(local_name!("type"))
            .unwrap_or("submit")
            .to_ascii_lowercase();
        if ty == "submit" && find_associated_form(doc, target.id).is_some() {
            return NativeClickOutcome::SubmitForm(Some(ext_id));
        }
    }
    NativeClickOutcome::Focused
}

fn find_associated_form(doc: &BaseDocument, start: NodeId) -> Option<NodeId> {
    if let Some(form_attr) = doc
        .get_node(start)
        .and_then(|n| n.element_data())
        .and_then(|e| e.attr(local_name!("form")))
    {
        if let Some(fid) = doc.get_element_by_id(form_attr) {
            return Some(fid);
        }
    }
    let mut cur = Some(start);
    for _ in 0..64 {
        let id = cur?;
        let node = doc.get_node(id)?;
        if node
            .element_data()
            .is_some_and(|e| &*e.name.local == "form")
        {
            return Some(id);
        }
        cur = node.parent;
    }
    None
}

fn first_form_id(doc: &BaseDocument) -> Option<NodeId> {
    doc.query_selector("form").ok().flatten()
}

fn collect_matching_radios(
    doc: &BaseDocument,
    target_nid: NodeId,
    name: Option<&str>,
    form_id: Option<NodeId>,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    let Some(target_name) = name.filter(|s| !s.is_empty()) else {
        return out;
    };
    let mut stack = vec![doc.root_node().id];
    while let Some(id) = stack.pop() {
        let Some(node) = doc.get_node(id) else {
            continue;
        };
        if id != target_nid && is_matching_radio(doc, node, target_name, form_id) {
            out.push(id);
        }
        for &cid in &node.children {
            stack.push(cid);
        }
    }
    out
}

fn is_matching_radio(
    doc: &BaseDocument,
    node: &Node,
    target_name: &str,
    form_id: Option<NodeId>,
) -> bool {
    let Some(elem) = node.element_data() else {
        return false;
    };
    if &*elem.name.local != "input" {
        return false;
    }
    let ty = elem
        .attr(local_name!("type"))
        .unwrap_or("")
        .to_ascii_lowercase();
    ty == "radio"
        && elem.attr(local_name!("name")) == Some(target_name)
        && find_associated_form(doc, node.id) == form_id
}

fn collect_form_fields(
    doc: &BaseDocument,
    form_nid: NodeId,
    trigger_nid: Option<NodeId>,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![doc.root_node().id];
    while let Some(id) = stack.pop() {
        let Some(node) = doc.get_node(id) else {
            continue;
        };
        if let Some((k, v)) = extract_form_control_entry(doc, node, form_nid, trigger_nid) {
            out.push((k, v));
        }
        for &cid in node.children.iter().rev() {
            stack.push(cid);
        }
    }
    out
}

fn extract_form_control_entry(
    doc: &BaseDocument,
    node: &Node,
    form_nid: NodeId,
    trigger_nid: Option<NodeId>,
) -> Option<(String, String)> {
    let elem = node.element_data()?;
    let tag = &*elem.name.local;
    if !matches!(tag, "input" | "textarea" | "select") {
        return None;
    }
    if elem.attr(local_name!("disabled")).is_some() {
        return None;
    }
    if find_associated_form(doc, node.id) != Some(form_nid) {
        return None;
    }
    let name = elem.attr(local_name!("name")).filter(|s| !s.is_empty())?;
    if tag == "input" {
        return extract_input_entry(doc, node, elem, name, trigger_nid);
    }
    let val = read_node_live_value(doc, node).unwrap_or_default();
    Some((name.to_string(), val))
}

fn extract_input_entry(
    doc: &BaseDocument,
    node: &Node,
    elem: &blitz_dom::ElementData,
    name: &str,
    trigger_nid: Option<NodeId>,
) -> Option<(String, String)> {
    let ty = elem
        .attr(local_name!("type"))
        .unwrap_or("text")
        .to_ascii_lowercase();
    if matches!(ty.as_str(), "button" | "reset" | "image" | "file") {
        return None;
    }
    if ty == "submit" && trigger_nid != Some(node.id) {
        return None;
    }
    if ty == "checkbox" || ty == "radio" {
        if !read_node_checked(node).unwrap_or(false) {
            return None;
        }
        let val = elem.attr(local_name!("value")).unwrap_or("on").to_string();
        return Some((name.to_string(), val));
    }
    let val = read_node_live_value(doc, node).unwrap_or_default();
    Some((name.to_string(), val))
}

/// Extracts `(tile_count, payload_tile_hashes, invalidated_hashes)` from encoded `KSC2` bytes.
pub fn ksc2_tile_metadata(frame_bytes: &[u8]) -> Result<(u32, Vec<u64>, Vec<u64>), String> {
    let frame = crate::paint::scene_v2::SceneFrameV2::decode(frame_bytes)
        .map_err(|e| format!("decode KSC2: {e}"))?;
    let payload_hashes: Vec<u64> = frame.tiles.iter().map(|t| t.content_hash).collect();
    let invalidated: Vec<u64> = frame
        .layers
        .iter()
        .flat_map(|layer| layer.invalidated_hashes.iter().copied())
        .collect();
    Ok((frame.tiles.len() as u32, payload_hashes, invalidated))
}

#[cfg(test)]
mod tests {
    use super::NativeBlitzDocument;
    use crate::paint::scene_v2::SceneFrameV2;

    #[test]
    fn native_host_renders_png_ksc0_ksc2_and_handles_mutations() {
        let html = r#"<!DOCTYPE html>
        <html>
          <head><title>Native Host Smoke</title></head>
          <body style="margin:0;background:#ffffff">
            <div id="box" style="width:120px;height:80px;background:#ff0000"></div>
            <p id="msg">initial</p>
          </body>
        </html>"#;
        let mut doc = NativeBlitzDocument::from_html(html, "https://example.test/", 320, 240);
        assert_eq!(doc.title(), "Native Host Smoke");
        assert_eq!(doc.viewport(), (320, 240));
        let box_id = doc.get_element_by_id("box");
        assert!(box_id > 0);
        let msg_id = doc.query_selector("#msg").expect("query #msg");
        assert!(msg_id > 0);
        assert_eq!(doc.text_content(msg_id as u32), "initial");
        assert_eq!(doc.element_from_point(10.0, 10.0), box_id);

        let rgba = doc.paint_rgba().expect("paint rgba");
        assert_eq!(rgba.len(), 320 * 240 * 4);
        assert_eq!(&rgba[0..4], &[255, 0, 0, 255]);

        let png = doc.paint_png().expect("paint png");
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        let ksc0 = doc.record_ksc0(0, 0);
        assert!(ksc0.starts_with(b"KSC0"));

        let ksc2 = doc.render_ksc2(2, 4, &[]);
        assert!(ksc2.starts_with(b"KSC2"));
        let decoded = SceneFrameV2::decode(&ksc2).expect("decode KSC2");
        assert_eq!(decoded.acked_scroll_seq, 2);
        assert_eq!(decoded.acked_input_seq, 4);
        assert!(!decoded.tiles.is_empty());

        let epoch_before = doc.layout_epoch();
        assert!(doc.set_node_text(msg_id as u32, "updated"));
        doc.resolve_layout();
        assert_ne!(doc.layout_epoch(), epoch_before);
        assert_eq!(doc.text_content(msg_id as u32), "updated");
    }

    #[test]
    fn native_host_dom_snapshot_form_controls_and_submission() {
        let html = r#"<!doctype html><html><head><title>Form Page</title></head>
        <body><form action="/submit" method="post">
          <input id="user" name="username" type="text" value="">
          <input id="agree" name="agree" type="checkbox">
          <select id="country" name="country">
            <option value="us">United States</option>
            <option value="ca">Canada</option>
          </select>
          <button id="go" type="submit">Go</button>
        </form></body></html>"#;
        let mut doc = NativeBlitzDocument::from_html(html, "https://app.example/login", 640, 480);
        let user_id = doc.get_element_by_id("user") as u32;
        let agree_id = doc.get_element_by_id("agree") as u32;
        let country_id = doc.get_element_by_id("country") as u32;
        let go_id = doc.get_element_by_id("go") as u32;
        assert!(doc.set_input_text(user_id, "alice"));
        assert_eq!(doc.get_input_value(user_id).as_deref(), Some("alice"));
        let clicked = doc.click_element(agree_id).expect("click checkbox");
        assert_eq!(clicked, super::NativeClickOutcome::ToggledCheckbox(true));
        let chosen = doc.select_option(country_id, "ca").expect("select ca");
        assert_eq!(chosen, "ca");
        let snap = doc.capture_dom_snapshot();
        assert_eq!(snap.title, "Form Page");
        assert!(snap.root.is_some());
        let sub = doc
            .inspect_form_submission(Some(go_id))
            .expect("inspect form submission");
        assert_eq!(sub.action, "/submit");
        assert_eq!(sub.method, "post");
        assert!(sub.fields.contains(&("username".into(), "alice".into())));
        assert!(sub.fields.contains(&("agree".into(), "on".into())));
        assert!(sub.fields.contains(&("country".into(), "ca".into())));
    }
}
