//! Go language plugin auto-registration.

inventory::submit! {
    crate::lang::register::LanguagePluginRegistrar(|| Box::new(crate::lang::go::GoPlugin))
}
