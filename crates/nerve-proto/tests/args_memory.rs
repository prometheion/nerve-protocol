//! A call's arguments may be megabytes (a file's content): reading them into
//! a type and checking them against a schema must not copy them.
//!
//! A test binary of its own, since it counts every allocation of the process
//! through its own allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use nerve_proto::rpc::params;
use nerve_proto::schema::validate_map;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// The system allocator, counting the bytes in use and the most since the
/// last reset.
struct Counting;

static IN_USE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = IN_USE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) };
        IN_USE.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The most bytes in use at once while `f` runs, above what was in use
/// before.
fn peak_of<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = IN_USE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let out = f();
    (out, PEAK.load(Ordering::SeqCst) - before)
}

#[derive(Deserialize)]
struct Write {
    path: String,
    content: String,
}

/// A type that keeps only the path, as a handler that reads one field.
#[derive(Deserialize)]
struct Named {
    path: String,
}

#[test]
fn a_large_argument_is_not_copied() {
    const MIB: usize = 1024 * 1024;
    let mut args = Map::new();
    args.insert("path".into(), json!("/w/a"));
    args.insert("content".into(), Value::String("x".repeat(4 * MIB)));
    // The type gets its own string, and nothing more: no copy of the map.
    let (w, took) = peak_of(|| params::<Write>(&args).unwrap());
    assert_eq!((w.path.as_str(), w.content.len()), ("/w/a", 4 * MIB));
    assert!(took < 4 * MIB + 64 * 1024, "params took {took} bytes");
    drop(w);
    // A type that leaves the content out costs nothing for it.
    let (n, took) = peak_of(|| params::<Named>(&args).unwrap());
    assert_eq!(n.path, "/w/a");
    assert!(took < 64 * 1024, "params took {took} bytes");
    let schema = json!({"type": "object", "properties": {
        "path": {"type": "string"}, "content": {"type": "string"}}});
    let (fits, took) = peak_of(|| validate_map(&schema, &args));
    assert_eq!(fits, Ok(()));
    assert!(took < 64 * 1024, "validate_map took {took} bytes");
}
