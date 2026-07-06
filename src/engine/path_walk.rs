//! Shared upward directory traversal.

use std::path::Path;

/// Action to take after visiting a directory during an upward walk.
pub(crate) enum WalkUpAction<T> {
    /// A result was found; stop and return it.
    Found(T),
    /// Stop walking without a result (e.g. hit a repository boundary).
    Stop,
    /// Keep walking to the parent directory.
    Continue,
}

/// Walk upward from `start` (using the parent when `start` is a file),
/// invoking `visit` on each directory until it returns [`WalkUpAction::Found`]
/// or [`WalkUpAction::Stop`], or the chain ends.
pub(crate) fn walk_up_dirs<T>(
    start: &Path,
    mut visit: impl FnMut(&Path) -> WalkUpAction<T>,
) -> Option<T> {
    let mut current = if start.is_file() {
        start.parent()?.to_path_buf()
    } else {
        start.to_path_buf()
    };
    loop {
        match visit(&current) {
            WalkUpAction::Found(result) => return Some(result),
            WalkUpAction::Stop => return None,
            WalkUpAction::Continue => {}
        }
        if !current.pop() {
            return None;
        }
    }
}
