use super::super::facts::GoUnitFacts;
use super::super::metadata::*;
use crate::core::ParsedUnit;
use crate::rules::{Finding, emit};
pub(crate) fn detect_cwe_434(unit: &ParsedUnit, _facts: &GoUnitFacts, out: &mut Vec<Finding>) {
    let file = unit.display_path.as_str();
    let source = unit.source.as_ref();

    let stores_client_filename = (source.contains("file.Filename")
        && source.contains("SaveUploadedFile(file, dest)"))
        || (source.contains("hdr.Filename") && source.contains("os.Create(dest)"));
    if !stores_client_filename {
        return;
    }
    let executable_web_serve_shape = (source.contains("/var/www/static/avatars")
        || source.contains("/static/avatars/"))
        && (source.contains("c.Redirect(http.StatusFound, \"/static/avatars/\"+file.Filename)")
            || source.contains(
                "http.Redirect(w, r, \"/static/avatars/\"+hdr.Filename, http.StatusFound)",
            ));
    if !executable_web_serve_shape {
        return;
    }
    if source.contains("unsupported file type")
        || source.contains("filepath.Ext(")
        || source.contains("hex.EncodeToString(")
    {
        return;
    }

    let start_byte = if let Some(idx) = source.find("file.Filename") {
        idx
    } else {
        source.find("hdr.Filename").unwrap_or(0)
    };
    let (line, col) = unit.line_col(start_byte);
    emit::push_finding(
        &META_CWE_434,
        file,
        line,
        col,
        "the upload is stored and later served using the client filename without an extension allow-list",
        out,
    );
}
