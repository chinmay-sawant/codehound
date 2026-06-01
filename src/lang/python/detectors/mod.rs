mod re_compile_in_loop;

pub use re_compile_in_loop::ReCompileInLoop;

pub fn all() -> Vec<Box<dyn crate::core::Detector>> {
    vec![Box::new(ReCompileInLoop)]
}
