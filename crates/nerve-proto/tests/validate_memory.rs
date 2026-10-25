//! `schema::validate` looks at a long array one item at a time: arguments of
//! a few megabytes, which the message limits let through, must not cost
//! memory per item on top of the parsed value.
//!
//! A test binary of its own, since it counts every allocation of the process
//! through its own allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use nerve_proto::schema::validate;
use serde_json::{Value, json};

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

#[test]
fn a_long_array_costs_no_memory_per_item() {
    let schema = json!({"type": "object", "properties": {
        "a": {"type": "array", "items": {"type": "integer", "minimum": 0}}}});
    let args = json!({"a": vec![Value::from(0); 200_000]});
    let before = IN_USE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let fits = validate(&schema, &args);
    let extra = PEAK.load(Ordering::SeqCst) - before;
    assert_eq!(fits, Ok(()));
    // A few frames and a path: far below one byte per item.
    assert!(extra < 64 * 1024, "validate took {extra} bytes");
    // The path of an item that does not fit is still written out.
    let mut bad = args;
    bad["a"][150_000] = json!(-1);
    let e = validate(&schema, &bad).unwrap_err();
    assert_eq!(e.field, "a[150000]");
}
