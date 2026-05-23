use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use toml_edit::{Array, DocumentMut, Item, Table, Value};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    SetStringArray {
        input: String,
        path: Vec<String>,
        key: String,
        values: Vec<String>,
    },
}

#[derive(Serialize)]
struct Response {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl Response {
    fn ok(output: String) -> Self {
        Self { ok: true, output: Some(output), error: None }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, output: None, error: Some(msg.into()) }
    }
}

fn handle(req: Request) -> Response {
    match req {
        Request::SetStringArray { input, path, key, values } => {
            set_string_array(&input, &path, &key, &values)
                .map(Response::ok)
                .unwrap_or_else(|e| Response::err(e.to_string()))
        }
    }
}

fn set_string_array(
    input: &str,
    path: &[String],
    key: &str,
    values: &[String],
) -> Result<String, Box<dyn std::error::Error>> {
    if path.is_empty() {
        return Err("path must contain at least one segment".into());
    }

    let mut doc: DocumentMut = if input.trim().is_empty() {
        DocumentMut::new()
    } else {
        input.parse()?
    };

    // Walk down the path, creating intermediate tables as needed.
    let tbl = descend(doc.as_table_mut(), path)?;

    // Build a fresh array of strings.
    let mut arr = Array::new();
    for v in values {
        arr.push(Value::from(v.as_str()));
    }

    // If the key exists, mutate in place so key prefix decor (which holds
    // preceding comments) and value decor (trailing comments) are preserved.
    if let Some(item) = tbl.get_mut(key) {
        if let Some(existing) = item.as_value_mut() {
            let decor = existing.decor().clone();
            let mut new_val = Value::Array(arr);
            *new_val.decor_mut() = decor;
            *existing = new_val;
            return Ok(doc.to_string());
        }
    }
    tbl.insert(key, Item::Value(Value::Array(arr)));

    Ok(doc.to_string())
}

/// Walk `tbl` following `path`, creating missing intermediate tables.
/// Returns a mutable reference to the deepest table.
fn descend<'a>(
    mut tbl: &'a mut Table,
    path: &[String],
) -> Result<&'a mut Table, Box<dyn std::error::Error>> {
    for segment in path {
        if !tbl.contains_key(segment) {
            tbl.insert(segment, Item::Table(Table::new()));
        }
        tbl = tbl
            .get_mut(segment)
            .and_then(|i| i.as_table_mut())
            .ok_or_else(|| format!("`{}` exists but is not a table", segment))?;
    }
    Ok(tbl)
}

fn main() {
    // Read one JSON request line from stdin. Line-based so the BEAM-side
    // port doesn't need to close stdin to signal EOF (closing the port from
    // Erlang loses subsequent stdout).
    let mut buf = String::new();
    let stdin = io::stdin();
    if let Err(e) = stdin.lock().read_line(&mut buf) {
        emit(&Response::err(format!("stdin read failed: {}", e)));
        std::process::exit(0);
    }
    let resp = match serde_json::from_str::<Request>(buf.trim_end()) {
        Ok(req) => handle(req),
        Err(e) => Response::err(format!("invalid request: {}", e)),
    };
    emit(&resp);
}

fn emit(resp: &Response) {
    let s = serde_json::to_string(resp).expect("serialize response");
    let stdout = io::stdout();
    let mut h = stdout.lock();
    let _ = h.write_all(s.as_bytes());
    let _ = h.write_all(b"\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn preserves_comments_and_unrelated_sections() {
        let input = r#"# top-level comment
# another line

[tools.licence_audit]
# allowed list
allow = ["MIT"] # trailing
deny = []

[other]
key = "value"
"#;
        let out = set_string_array(
            input,
            &path(&["tools", "licence_audit"]),
            "allow",
            &["MIT".to_string(), "Apache-2.0".to_string()],
        )
        .expect("ok");

        assert!(out.contains("# top-level comment"), "top comment lost: {}", out);
        assert!(out.contains("# another line"), "second comment lost");
        assert!(out.contains("# allowed list"), "table comment lost");
        assert!(out.contains("# trailing"), "trailing inline comment lost");
        assert!(out.contains("[other]"), "unrelated section lost");
        assert!(out.contains("\"Apache-2.0\""), "new value missing");
    }

    #[test]
    fn empty_input_creates_nested_table() {
        let out = set_string_array(
            "",
            &path(&["tools", "licence_audit"]),
            "allow",
            &["MIT".to_string()],
        )
        .unwrap();
        assert!(out.contains("[tools.licence_audit]"), "nested header missing: {}", out);
        assert!(out.contains("\"MIT\""));
    }

    #[test]
    fn creates_subtable_in_existing_parent() {
        let input = "[tools]\nother = \"keep\"\n";
        let out = set_string_array(
            input,
            &path(&["tools", "licence_audit"]),
            "allow",
            &["MIT".to_string()],
        )
        .unwrap();
        assert!(out.contains("other = \"keep\""), "sibling key lost: {}", out);
        assert!(out.contains("licence_audit"));
        assert!(out.contains("\"MIT\""));
    }

    #[test]
    fn single_segment_path_still_works() {
        let out =
            set_string_array("", &path(&["licences"]), "allow", &["MIT".to_string()]).unwrap();
        assert!(out.contains("[licences]"));
        assert!(out.contains("\"MIT\""));
    }

    #[test]
    fn invalid_toml_errors() {
        let err = set_string_array("not = = valid", &path(&["x"]), "y", &[]).unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn empty_path_errors() {
        let err = set_string_array("", &[], "y", &[]).unwrap_err();
        assert!(err.to_string().contains("path"));
    }
}
