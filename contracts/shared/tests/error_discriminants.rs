use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Recursively collect all `.rs` files under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Extract the discriminant values from a `#[contracterror]` enum body.
fn extract_discriminants(source: &str) -> Vec<u32> {
    let mut discriminants = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if let Some(idx) = line.find('=') {
            let value = line[idx + 1..].trim().trim_end_matches(',').trim();
            if let Ok(discriminant) = value.parse::<u32>() {
                discriminants.push(discriminant);
            }
        }
    }
    discriminants
}

/// Validate that a single `#[contracterror]` enum has unique and sequential
/// discriminants.
fn validate_enum_discriminants(enum_name: &str, source: &str) {
    let discriminants = extract_discriminants(source);
    assert!(
        !discriminants.is_empty(),
        "{enum_name}: no discriminants found"
    );

    let mut seen = BTreeSet::new();
    for discriminant in &discriminants {
        assert!(
            seen.insert(*discriminant),
            "{enum_name}: duplicate discriminant {discriminant}"
        );
    }

    let mut sorted = discriminants.clone();
    sorted.sort_unstable();
    for window in sorted.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "{enum_name}: non-sequential discriminants {} and {}",
            window[0],
            window[1]
        );
    }
}

/// Scan every `.rs` file under each contract's `src/` directory for
/// `#[contracterror]` enums and validate their discriminants. This ensures
/// contracts that declare their error enum in `types.rs` (rather than
/// `lib.rs`) are actually inspected.
#[test]
fn validate_error_enum_discriminants() {
    let contracts_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("shared crate should live under contracts/");

    let mut checked = 0usize;
    let entries = fs::read_dir(contracts_dir).expect("contracts directory should be readable");
    for entry in entries.flatten() {
        let contract_path = entry.path();
        if !contract_path.is_dir() {
            continue;
        }

        let src_path = contract_path.join("src");
        if !src_path.is_dir() {
            continue;
        }

        let mut rs_files = Vec::new();
        collect_rs_files(&src_path, &mut rs_files);

        for file in rs_files {
            let source = match fs::read_to_string(&file) {
                Ok(source) => source,
                Err(_) => continue,
            };
            if !source.contains("#[contracterror]") {
                continue;
            }

            let enum_name = file
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>");
            validate_enum_discriminants(enum_name, &source);
            checked += 1;
        }
    }

    assert!(checked > 0, "no #[contracterror] enums were inspected");
}
