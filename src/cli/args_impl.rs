//! `impl Cli` — the three accessor methods (`generate_baseline`,
//! `scan_context`, `export_options`).

use crate::core::ScanContext;
use crate::engine::build_scan_context;
use crate::export::ExportOptions;

use super::args::Cli;

impl Cli {
    pub fn scan_context(&self, config: Option<crate::engine::SlopguardConfig>) -> ScanContext {
        let cli_set_fail_policy = self.severity.is_explicit();
        let mut ctx = build_scan_context(
            self.only.clone(),
            self.skip.clone(),
            self.severity.fail_policy(),
            config,
            cli_set_fail_policy,
            self.debug_timing,
            self.diagnostics.is_some(),
            self.diagnostics_summary,
        );
        if self.bp_only {
            ctx.only = Some(["BP-*".to_string()].into_iter().collect());
            ctx.bad_practices_enabled = true;
        }
        if self.no_bp {
            ctx.bad_practices_enabled = false;
        }
        if self.taint {
            ctx.taint_enabled = true;
        }
        if self.no_taint {
            ctx.taint_enabled = false;
        }
        if self.taint_show_paths {
            ctx.taint_show_paths = true;
        }
        ctx.show_ignored = self.show_ignored;
        ctx
    }

    pub fn export_options(&self) -> ExportOptions {
        ExportOptions {
            export_context: !self.no_context,
            export_chunks: !self.no_chunks,
            chunk_size: self.chunk_size,
            context_output_dir: self.context_output_dir.clone(),
            chunks_output_dir: self.chunks_output_dir.clone(),
        }
    }
}
