//! Go performance detectors.

mod map_alloc_in_loop;
mod regexp_in_loop;
mod slice_rebuild_in_loop;
mod string_concat_in_loop;

pub use map_alloc_in_loop::MapAllocInLoop;
pub use regexp_in_loop::RegexpInLoop;
pub use slice_rebuild_in_loop::SliceRebuildInLoop;
pub use string_concat_in_loop::StringConcatInLoop;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![
        Box::new(RegexpInLoop),
        Box::new(StringConcatInLoop),
        Box::new(SliceRebuildInLoop),
        Box::new(MapAllocInLoop),
    ]
}
