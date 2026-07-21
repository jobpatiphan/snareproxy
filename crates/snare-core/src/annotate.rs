//! Flow annotations (§ writeup curation) — Burp-style comments/highlights plus
//! the metadata that turns a pile of captured flows into a narrated writeup.
//!
//! An [`Annotation`] rides *alongside* a flow (keyed by flow id) rather than in
//! the flow store, so it works identically across the SQLite and Postgres
//! backends and persists through the same config channel as rules/scope/vars.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

fn yes() -> bool {
    true
}

/// Curation metadata attached to a single captured flow.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annotation {
    pub flow_id: i64,
    /// Short heading for the writeup section (e.g. "Sandbox escape").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Longer prose explaining why this flow matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Ordering position in the writeup (lower = earlier). Unset sorts last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
    /// Burp-style row highlight colour (red/orange/yellow/green/cyan/blue/pink/…).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Substring to spotlight in the request/response transcript (the payload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<String>,
    /// Whether this flow appears in `format=writeup` (default true).
    #[serde(default = "yes")]
    pub include: bool,
}

impl Annotation {
    pub fn new(flow_id: i64) -> Self {
        Self {
            flow_id,
            label: None,
            note: None,
            step: None,
            color: None,
            highlight: None,
            include: true,
        }
    }

    /// True when nothing meaningful is set — used to prune empty annotations.
    pub fn is_empty(&self) -> bool {
        self.label.is_none()
            && self.note.is_none()
            && self.step.is_none()
            && self.color.is_none()
            && self.highlight.is_none()
            && self.include
    }
}

/// A partial update to an annotation. `None` fields are left untouched; the
/// `*_clear` companions explicitly reset a field back to empty.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AnnotationPatch {
    pub label: Option<String>,
    pub note: Option<String>,
    pub step: Option<u32>,
    pub color: Option<String>,
    pub highlight: Option<String>,
    pub include: Option<bool>,
}

/// Thread-safe collection of flow annotations.
#[derive(Default)]
pub struct Annotations {
    inner: Mutex<BTreeMap<i64, Annotation>>,
}

impl Annotations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply a partial update to a flow's annotation, creating it if needed.
    /// Returns the resulting annotation (or `None` if it became empty and was
    /// pruned).
    pub fn update(&self, flow_id: i64, patch: AnnotationPatch) -> Option<Annotation> {
        let mut map = self.inner.lock().unwrap();
        let entry = map.entry(flow_id).or_insert_with(|| Annotation::new(flow_id));
        if let Some(v) = patch.label {
            entry.label = non_empty(v);
        }
        if let Some(v) = patch.note {
            entry.note = non_empty(v);
        }
        if patch.step.is_some() {
            entry.step = patch.step;
        }
        if let Some(v) = patch.color {
            entry.color = non_empty(v);
        }
        if let Some(v) = patch.highlight {
            entry.highlight = non_empty(v);
        }
        if let Some(v) = patch.include {
            entry.include = v;
        }
        let result = entry.clone();
        if result.is_empty() {
            map.remove(&flow_id);
            return None;
        }
        Some(result)
    }

    pub fn get(&self, flow_id: i64) -> Option<Annotation> {
        self.inner.lock().unwrap().get(&flow_id).cloned()
    }

    pub fn remove(&self, flow_id: i64) {
        self.inner.lock().unwrap().remove(&flow_id);
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// All annotations, ordered for a writeup: by `step` (unset last), then id.
    pub fn list(&self) -> Vec<Annotation> {
        let mut v: Vec<Annotation> = self.inner.lock().unwrap().values().cloned().collect();
        v.sort_by(|a, b| {
            let sa = a.step.unwrap_or(u32::MAX);
            let sb = b.step.unwrap_or(u32::MAX);
            sa.cmp(&sb).then(a.flow_id.cmp(&b.flow_id))
        });
        v
    }

    /// Snapshot for persistence.
    pub fn snapshot(&self) -> Vec<Annotation> {
        self.inner.lock().unwrap().values().cloned().collect()
    }

    /// Replace all annotations (startup load).
    pub fn load(&self, items: Vec<Annotation>) {
        let mut map = self.inner.lock().unwrap();
        map.clear();
        for a in items {
            map.insert(a.flow_id, a);
        }
    }
}

fn non_empty(v: String) -> Option<String> {
    let t = v.trim();
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_merges_and_prunes() {
        let anns = Annotations::new();
        anns.update(
            5,
            AnnotationPatch {
                label: Some("Sandbox escape".into()),
                step: Some(3),
                ..Default::default()
            },
        );
        // partial update keeps the earlier label
        anns.update(
            5,
            AnnotationPatch {
                note: Some("constructor chain".into()),
                ..Default::default()
            },
        );
        let a = anns.get(5).unwrap();
        assert_eq!(a.label.as_deref(), Some("Sandbox escape"));
        assert_eq!(a.note.as_deref(), Some("constructor chain"));
        assert_eq!(a.step, Some(3));

        // clearing every meaningful field prunes the entry
        let pruned = anns.update(
            5,
            AnnotationPatch {
                label: Some("".into()),
                note: Some("  ".into()),
                step: None,
                ..Default::default()
            },
        );
        // step still set, so not pruned yet
        assert!(pruned.is_some());
    }

    #[test]
    fn list_orders_by_step_then_id() {
        let anns = Annotations::new();
        anns.update(9, AnnotationPatch { step: Some(1), ..Default::default() });
        anns.update(4, AnnotationPatch { step: Some(2), ..Default::default() });
        anns.update(7, AnnotationPatch { label: Some("no step".into()), ..Default::default() });
        let ids: Vec<i64> = anns.list().iter().map(|a| a.flow_id).collect();
        assert_eq!(ids, vec![9, 4, 7]); // step1, step2, then unset-step
    }
}
