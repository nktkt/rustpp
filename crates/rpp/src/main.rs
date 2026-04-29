use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_help();
        return ExitCode::SUCCESS;
    };

    match command.as_str() {
        "audit" => {
            let root = args.next().unwrap_or_else(|| ".".to_string());
            match audit(Path::new(&root)) {
                Ok(has_unsafe_keyword) => {
                    if has_unsafe_keyword {
                        ExitCode::from(2)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(error) => {
                    eprintln!("rpp audit: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        "ci" => ci(args.collect()),
        "check" => rpp_check(args.collect()),
        "test" => run_cargo("test", args.collect()),
        "build" => run_cargo("build", args.collect()),
        "effects" => effects(args.collect()),
        "policy" => policy(args.collect()),
        "sbom" => sbom(args.collect()),
        "report" => report(args.collect()),
        "prove" => prove(args.collect()),
        "lower" => lower(args.next()),
        "expand" => expand(args.next()),
        "new" => match args.next() {
            Some(name) => create_project(&name),
            None => {
                eprintln!("rpp new: missing project name");
                ExitCode::FAILURE
            }
        },
        "migrate" => migrate(args.collect()),
        "help" | "--help" | "-h" => {
            print_help();
            ExitCode::SUCCESS
        }
        unknown => {
            eprintln!("unknown rpp command: {unknown}");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "Rust++ MVP tooling\n\nUSAGE:\n    rpp <command>\n\nCOMMANDS:\n    new <name>                  Create a Rust++ MVP project\n    ci [--report F]             Run policy, check, test, and report\n    check [--no-policy] [args]  Enforce policy, then run cargo check\n    test [args...]              Run cargo test\n    build [args...]             Run cargo build\n    audit [path]                Report unsafe usage and unsafe boundaries\n    effects [--deny A,B] [path] Report and optionally deny effects\n    policy [--config F] [path]  Enforce rustpp.toml policy\n    sbom [--json] [Cargo.lock]  Emit a minimal dependency SBOM\n    report [path]               Emit a JSON audit/effect/policy/SBOM report\n    migrate [--json] [path]     Suggest scan-only Rust++ migration candidates\n    prove [--json] [path]       Inventory contract annotations\n    lower <file.rpp>            Lower Rust++ syntax preview to Rust\n    expand <file>               Print the current lowering view\n"
    );
}

fn run_cargo(command: &str, args: Vec<String>) -> ExitCode {
    let status = Command::new("cargo").arg(command).args(args).status();

    match status {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("failed to run cargo {command}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn ci(args: Vec<String>) -> ExitCode {
    let config = match parse_ci_args(args) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("rpp ci: {message}");
            return ExitCode::FAILURE;
        }
    };

    match enforce_policy_if_present(&config.root, &config.config_path) {
        Ok(()) => {}
        Err(CheckFailure::Policy(exit_code)) => return exit_code,
        Err(CheckFailure::Io(error)) => {
            eprintln!("rpp ci: policy check failed: {error}");
            return ExitCode::FAILURE;
        }
    }

    if let Err(exit_code) = run_cargo_step("check", &["--workspace"]) {
        return exit_code;
    }

    if let Err(exit_code) = run_cargo_step("test", &["--workspace"]) {
        return exit_code;
    }

    if let Err(exit_code) = run_report_step(&config) {
        return exit_code;
    }

    println!("rpp ci: passed");
    ExitCode::SUCCESS
}

fn parse_ci_args(args: Vec<String>) -> Result<CiConfig, String> {
    let mut config = CiConfig {
        root: PathBuf::from("."),
        config_path: PathBuf::from("rustpp.toml"),
        lock_path: PathBuf::from("Cargo.lock"),
        report_path: None,
    };
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--report" {
            let Some(value) = args.get(index + 1) else {
                return Err("--report requires a file path".to_string());
            };
            config.report_path = Some(PathBuf::from(value));
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--report=") {
            config.report_path = Some(PathBuf::from(value));
            index += 1;
        } else if arg == "--config" {
            let Some(value) = args.get(index + 1) else {
                return Err("--config requires a file path".to_string());
            };
            config.config_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--config=") {
            config.config_path = PathBuf::from(value);
            index += 1;
        } else if arg == "--lockfile" {
            let Some(value) = args.get(index + 1) else {
                return Err("--lockfile requires a file path".to_string());
            };
            config.lock_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--lockfile=") {
            config.lock_path = PathBuf::from(value);
            index += 1;
        } else if arg == "--root" {
            let Some(value) = args.get(index + 1) else {
                return Err("--root requires a path".to_string());
            };
            config.root = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--root=") {
            config.root = PathBuf::from(value);
            index += 1;
        } else {
            config.root = PathBuf::from(arg);
            index += 1;
        }
    }

    Ok(config)
}

fn run_cargo_step(command: &str, args: &[&str]) -> Result<(), ExitCode> {
    match Command::new("cargo").arg(command).args(args).status() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(ExitCode::from(status.code().unwrap_or(1) as u8)),
        Err(error) => {
            eprintln!("rpp ci: failed to run cargo {command}: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn run_report_step(config: &CiConfig) -> Result<(), ExitCode> {
    let Some(report_path) = &config.report_path else {
        return match report(report_args(config)) {
            ExitCode::SUCCESS => Ok(()),
            exit_code => Err(exit_code),
        };
    };

    let output = match fs::File::create(report_path) {
        Ok(output) => output,
        Err(error) => {
            eprintln!("rpp ci: {}: {error}", report_path.display());
            return Err(ExitCode::FAILURE);
        }
    };

    let current_exe = match env::current_exe() {
        Ok(current_exe) => current_exe,
        Err(error) => {
            eprintln!("rpp ci: could not locate current executable: {error}");
            return Err(ExitCode::FAILURE);
        }
    };

    match Command::new(current_exe)
        .arg("report")
        .args(report_args(config))
        .stdout(Stdio::from(output))
        .status()
    {
        Ok(status) if status.success() => {
            println!("rpp ci: wrote report to {}", report_path.display());
            Ok(())
        }
        Ok(status) => Err(ExitCode::from(status.code().unwrap_or(1) as u8)),
        Err(error) => {
            eprintln!("rpp ci: failed to run report: {error}");
            Err(ExitCode::FAILURE)
        }
    }
}

fn report_args(config: &CiConfig) -> Vec<String> {
    vec![
        config.root.display().to_string(),
        "--config".to_string(),
        config.config_path.display().to_string(),
        "--lockfile".to_string(),
        config.lock_path.display().to_string(),
    ]
}

fn rpp_check(args: Vec<String>) -> ExitCode {
    let mut run_policy_first = true;
    let mut config_path = PathBuf::from("rustpp.toml");
    let mut root = PathBuf::from(".");
    let mut cargo_args = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            cargo_args.extend(args[index + 1..].iter().cloned());
            break;
        } else if arg == "--no-policy" {
            run_policy_first = false;
            index += 1;
        } else if arg == "--config" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp check: --config requires a file path");
                return ExitCode::FAILURE;
            };
            config_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--config=") {
            config_path = PathBuf::from(value);
            index += 1;
        } else if arg == "--root" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp check: --root requires a path");
                return ExitCode::FAILURE;
            };
            root = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--root=") {
            root = PathBuf::from(value);
            index += 1;
        } else {
            cargo_args.push(arg.clone());
            index += 1;
        }
    }

    if run_policy_first {
        match enforce_policy_if_present(&root, &config_path) {
            Ok(()) => {}
            Err(CheckFailure::Policy(exit_code)) => return exit_code,
            Err(CheckFailure::Io(error)) => {
                eprintln!("rpp check: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    run_cargo("check", cargo_args)
}

fn audit(root: &Path) -> io::Result<bool> {
    let mut report = AuditReport::default();
    collect_audit_report(root, &mut report)?;

    if report.unsafe_findings.is_empty() {
        println!("rpp audit: no unsafe usage found");
    } else {
        println!("rpp audit: unsafe usage found");
        for finding in &report.unsafe_findings {
            println!(
                "{}:{}: {}",
                finding.path.display(),
                finding.line,
                finding.text.trim()
            );
        }
    }

    if !report.boundaries.is_empty() {
        println!("rpp audit: unsafe boundaries found");
        for boundary in &report.boundaries {
            println!(
                "{}:{}: reason=\"{}\" audit=\"{}\"",
                boundary.path.display(),
                boundary.line,
                boundary.reason,
                boundary.audit
            );
        }
    }

    if !report.metadata_errors.is_empty() {
        eprintln!("rpp audit: unsafe boundary metadata errors");
        for finding in &report.metadata_errors {
            eprintln!(
                "{}:{}: {}",
                finding.path.display(),
                finding.line,
                finding.text.trim()
            );
        }
    }

    Ok(!report.unsafe_findings.is_empty() || !report.metadata_errors.is_empty())
}

fn collect_audit_findings(path: &Path, findings: &mut Vec<Finding>) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_audit_findings(&entry?.path(), findings)?;
        }
        return Ok(());
    }

    if !is_source_file(path) {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    for (index, line) in source.lines().enumerate() {
        if contains_unsafe_keyword(line) {
            findings.push(Finding {
                path: path.to_path_buf(),
                line: index + 1,
                text: line.to_string(),
            });
        }
    }

    Ok(())
}

fn collect_audit_report(path: &Path, report: &mut AuditReport) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_audit_report(&entry?.path(), report)?;
        }
        return Ok(());
    }

    if !is_source_file(path) {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    for (index, line) in source.lines().enumerate() {
        if contains_unsafe_keyword(line) {
            report.unsafe_findings.push(Finding {
                path: path.to_path_buf(),
                line: index + 1,
                text: line.to_string(),
            });
        }

        if let Some(boundary) = parse_unsafe_boundary_line(line) {
            match boundary {
                Ok((reason, audit)) => report.boundaries.push(UnsafeBoundaryFinding {
                    path: path.to_path_buf(),
                    line: index + 1,
                    reason,
                    audit,
                }),
                Err(message) => report.metadata_errors.push(Finding {
                    path: path.to_path_buf(),
                    line: index + 1,
                    text: message,
                }),
            }
        }
    }

    Ok(())
}

fn parse_unsafe_boundary_line(line: &str) -> Option<Result<(String, String), String>> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with("#[unsafe_boundary") {
        return None;
    }

    let reason = parse_attribute_string_value(trimmed, "reason");
    let audit = parse_attribute_string_value(trimmed, "audit");

    match (reason, audit) {
        (Some(reason), Some(audit)) => Some(Ok((reason, audit))),
        _ => Some(Err(
            "unsafe boundary requires `reason = \"...\"` and `audit = \"...\"`".to_string(),
        )),
    }
}

fn parse_attribute_string_value(line: &str, key: &str) -> Option<String> {
    let key_index = line.find(key)?;
    let mut rest = &line[key_index + key.len()..];
    rest = rest.trim_start();
    rest = rest.strip_prefix('=')?.trim_start();
    rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn should_skip(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| matches!(name, ".git" | "target"))
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| matches!(ext, "rs" | "rpp"))
}

fn prove(args: Vec<String>) -> ExitCode {
    let mut root = PathBuf::from(".");
    let mut json = false;

    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            root = PathBuf::from(arg);
        }
    }

    let mut annotations = Vec::new();
    match collect_contract_annotations(&root, &mut annotations) {
        Ok(()) => {
            if json {
                print_json_contract_inventory(&annotations);
            } else {
                print_text_contract_inventory(&annotations);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rpp prove: {error}");
            ExitCode::FAILURE
        }
    }
}

fn migrate(args: Vec<String>) -> ExitCode {
    let mut root = PathBuf::from(".");
    let mut json = false;

    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            root = PathBuf::from(arg);
        }
    }

    let mut findings = Vec::new();
    if let Err(error) = collect_migration_findings(&root, &mut findings) {
        eprintln!("rpp migrate: {error}");
        return ExitCode::FAILURE;
    }

    if json {
        print_json_migration_findings(&findings);
    } else {
        print_text_migration_findings(&findings);
    }

    ExitCode::SUCCESS
}

fn collect_migration_findings(path: &Path, findings: &mut Vec<MigrationFinding>) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_migration_findings(&entry?.path(), findings)?;
        }
        return Ok(());
    }

    if path.extension().and_then(OsStr::to_str) != Some("rs") {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    let mut attributes = Vec::new();
    let mut refined_type_depth = None;
    for (index, line) in source.lines().enumerate() {
        let trimmed = line.trim_start();
        let starts_refined_type =
            refined_type_depth.is_none() && trimmed.starts_with("refined_type!");
        let inside_refined_type = refined_type_depth.is_some() || starts_refined_type;

        if trimmed.starts_with("#[") {
            attributes.push(trimmed.to_string());
            update_refined_type_depth(&mut refined_type_depth, trimmed, starts_refined_type);
            continue;
        }

        if trimmed.is_empty() || trimmed.starts_with("//") {
            update_refined_type_depth(&mut refined_type_depth, trimmed, starts_refined_type);
            continue;
        }

        collect_migration_line_findings(
            path,
            index + 1,
            line,
            &attributes,
            inside_refined_type,
            findings,
        );
        attributes.clear();
        update_refined_type_depth(&mut refined_type_depth, trimmed, starts_refined_type);
    }

    Ok(())
}

fn update_refined_type_depth(depth: &mut Option<usize>, line: &str, starts_refined_type: bool) {
    if starts_refined_type && depth.is_none() {
        *depth = Some(0);
    }

    let Some(current) = *depth else {
        return;
    };

    let open_braces = line.chars().filter(|character| *character == '{').count();
    let close_braces = line.chars().filter(|character| *character == '}').count();
    let next = current
        .saturating_add(open_braces)
        .saturating_sub(close_braces);

    if next == 0 && (open_braces > 0 || close_braces > 0) {
        *depth = None;
    } else {
        *depth = Some(next);
    }
}

fn collect_migration_line_findings(
    path: &Path,
    line: usize,
    source_line: &str,
    attributes: &[String],
    inside_refined_type: bool,
    findings: &mut Vec<MigrationFinding>,
) {
    if inside_refined_type {
        return;
    }

    let trimmed = source_line.trim_start();
    let has_attribute = |name: &str| attributes.iter().any(|attr| attr.starts_with(name));

    if contains_unsafe_keyword(source_line) && !has_attribute("#[unsafe_boundary") {
        findings.push(MigrationFinding {
            path: path.to_path_buf(),
            line,
            kind: "unsafe-boundary".to_string(),
            detail: "unsafe keyword is visible without unsafe boundary metadata".to_string(),
            suggestion: "Add #[unsafe_boundary(reason = \"...\", audit = \"YYYY-MM\")] to the boundary or wrapper.".to_string(),
        });
    }

    if let Some(name) = declaration_name(trimmed, "struct") {
        if !has_attribute("#[component") {
            if is_component_candidate_struct(trimmed) {
                findings.push(MigrationFinding {
                    path: path.to_path_buf(),
                    line,
                    kind: "component".to_string(),
                    detail: format!("struct `{name}` may be a Rust++ component candidate"),
                    suggestion: format!("Consider #[component] on `{name}` if it owns state, dependencies, or lifecycle."),
                });
            }
        }
    }

    if let Some(name) = declaration_name(trimmed, "trait") {
        findings.push(MigrationFinding {
            path: path.to_path_buf(),
            line,
            kind: "protocol".to_string(),
            detail: format!("trait `{name}` may be a Rust++ protocol candidate"),
            suggestion: format!(
                "Consider `protocol {name}` in .rpp if the trait represents an API contract."
            ),
        });
    }

    if is_async_function_signature(trimmed) && !has_attribute("#[effects") {
        findings.push(MigrationFinding {
            path: path.to_path_buf(),
            line,
            kind: "effect".to_string(),
            detail: "async function has no Rust++ effect annotation".to_string(),
            suggestion: "Add #[effects(...)] or .rpp `effects(...)` once the IO/capability surface is known.".to_string(),
        });
    }

    if let Some((name, inner)) = primitive_type_alias(trimmed) {
        findings.push(MigrationFinding {
            path: path.to_path_buf(),
            line,
            kind: "refinement-type".to_string(),
            detail: format!("type alias `{name}` wraps primitive `{inner}`"),
            suggestion: format!(
                "Consider `contract type {name} = {inner} where |value| ...;` or refined_type!."
            ),
        });
    }

    if function_has_primitive_domain_parameter(trimmed) {
        findings.push(MigrationFinding {
            path: path.to_path_buf(),
            line,
            kind: "refinement-parameter".to_string(),
            detail: "function signature contains primitive domain parameter names".to_string(),
            suggestion:
                "Consider replacing raw amount/count/size/id primitives with refined domain types."
                    .to_string(),
        });
    }
}

fn declaration_name(line: &str, keyword: &str) -> Option<String> {
    let rest = line.strip_prefix(keyword)?.trim_start();
    let name: String = rest
        .chars()
        .take_while(|character| *character == '_' || character.is_ascii_alphanumeric())
        .collect();
    (!name.is_empty()).then_some(name)
}

fn is_component_candidate_struct(line: &str) -> bool {
    let before_body = line.split_once('{').map_or(line, |(head, _)| head);
    !before_body.contains('(') && !line.trim_end().ends_with(';')
}

fn is_async_function_signature(line: &str) -> bool {
    line.starts_with("async fn ") || line.contains(" async fn ")
}

fn primitive_type_alias(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("type ")?;
    let (name, rhs) = rest.split_once('=')?;
    let name = name.trim();
    let inner = rhs.trim().trim_end_matches(';').trim();

    if is_identifier(name) && is_primitive_domain_type(inner) {
        Some((name.to_string(), inner.to_string()))
    } else {
        None
    }
}

fn is_primitive_domain_type(value: &str) -> bool {
    matches!(
        value,
        "String"
            | "str"
            | "usize"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
    )
}

fn function_has_primitive_domain_parameter(line: &str) -> bool {
    (line.starts_with("fn ") || line.starts_with("async fn ") || line.contains(" fn "))
        && DOMAIN_PARAMETER_NAMES
            .iter()
            .any(|name| line.contains(&format!("{name}:")) || line.contains(&format!("{name}: ")))
        && PRIMITIVE_PARAMETER_TYPES
            .iter()
            .any(|ty| line.contains(&format!(": {ty}")) || line.contains(&format!(":{ty}")))
}

fn print_text_migration_findings(findings: &[MigrationFinding]) {
    if findings.is_empty() {
        println!("rpp migrate: no migration candidates found");
        return;
    }

    println!("rpp migrate: found {} candidate(s)", findings.len());
    for finding in findings {
        println!(
            "{}:{}: [{}] {}",
            finding.path.display(),
            finding.line,
            finding.kind,
            finding.detail
        );
        println!("  suggestion: {}", finding.suggestion);
    }
}

fn print_json_migration_findings(findings: &[MigrationFinding]) {
    println!("{{");
    println!("  \"format\": \"rustpp-migrate-v0\",");
    println!("  \"candidates\": [");
    for (index, finding) in findings.iter().enumerate() {
        let comma = if index + 1 == findings.len() { "" } else { "," };
        println!(
            "    {{ \"path\": \"{}\", \"line\": {}, \"kind\": \"{}\", \"detail\": \"{}\", \"suggestion\": \"{}\" }}{}",
            json_escape(&finding.path.display().to_string()),
            finding.line,
            json_escape(&finding.kind),
            json_escape(&finding.detail),
            json_escape(&finding.suggestion),
            comma
        );
    }
    println!("  ]");
    println!("}}");
}

const DOMAIN_PARAMETER_NAMES: &[&str] = &["amount", "count", "size", "len", "id"];
const PRIMITIVE_PARAMETER_TYPES: &[&str] = &[
    "usize", "isize", "u8", "u16", "u32", "u64", "u128", "i8", "i16", "i32", "i64", "i128",
    "String",
];

fn effects(args: Vec<String>) -> ExitCode {
    let mut root = PathBuf::from(".");
    let mut denied = Vec::new();
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--deny" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp effects: --deny requires a comma-separated value");
                return ExitCode::FAILURE;
            };
            extend_denied_effects(&mut denied, value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--deny=") {
            extend_denied_effects(&mut denied, value);
            index += 1;
        } else {
            root = PathBuf::from(arg);
            index += 1;
        }
    }

    let mut findings = Vec::new();
    match collect_effect_findings(&root, &mut findings) {
        Ok(()) => report_effects(&findings, &denied),
        Err(error) => {
            eprintln!("rpp effects: {error}");
            ExitCode::FAILURE
        }
    }
}

fn extend_denied_effects(denied: &mut Vec<String>, value: &str) {
    denied.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|effect| !effect.is_empty())
            .map(str::to_string),
    );
}

fn report_effects(findings: &[EffectFinding], denied: &[String]) -> ExitCode {
    if findings.is_empty() {
        println!("rpp effects: no effect annotations found");
        return ExitCode::SUCCESS;
    }

    println!("rpp effects: found {} annotation(s)", findings.len());
    for finding in findings {
        println!(
            "{}:{}: {}",
            finding.path.display(),
            finding.line,
            finding.effects.join(", ")
        );
    }

    let mut denied_findings = Vec::new();
    for finding in findings {
        for effect in &finding.effects {
            if denied.iter().any(|denied| denied == effect) {
                denied_findings.push((finding, effect));
            }
        }
    }

    if denied_findings.is_empty() {
        return ExitCode::SUCCESS;
    }

    eprintln!("rpp effects: denied effect usage found");
    for (finding, effect) in denied_findings {
        eprintln!("{}:{}: {effect}", finding.path.display(), finding.line);
    }

    ExitCode::from(2)
}

fn policy(args: Vec<String>) -> ExitCode {
    let mut config_path = PathBuf::from("rustpp.toml");
    let mut root = PathBuf::from(".");
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--config" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp policy: --config requires a file path");
                return ExitCode::FAILURE;
            };
            config_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--config=") {
            config_path = PathBuf::from(value);
            index += 1;
        } else {
            root = PathBuf::from(arg);
            index += 1;
        }
    }

    match enforce_policy(&root, &config_path) {
        Ok(0) => {
            println!("rpp policy: passed");
            ExitCode::SUCCESS
        }
        Ok(violations) => {
            eprintln!("rpp policy: {violations} violation(s)");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("rpp policy: {}: {error}", config_path.display());
            ExitCode::FAILURE
        }
    }
}

fn sbom(args: Vec<String>) -> ExitCode {
    let mut lock_path = PathBuf::from("Cargo.lock");
    let mut json = false;

    for arg in args {
        if arg == "--json" {
            json = true;
        } else {
            lock_path = PathBuf::from(arg);
        }
    }

    let source = match fs::read_to_string(&lock_path) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("rpp sbom: {}: {error}", lock_path.display());
            return ExitCode::FAILURE;
        }
    };

    let packages = match parse_cargo_lock_packages(&source) {
        Ok(packages) => packages,
        Err(error) => {
            eprintln!("rpp sbom: {}: {error}", lock_path.display());
            return ExitCode::FAILURE;
        }
    };

    if json {
        print_json_sbom(&packages);
    } else {
        print_text_sbom(&packages);
    }

    ExitCode::SUCCESS
}

fn report(args: Vec<String>) -> ExitCode {
    let mut root = PathBuf::from(".");
    let mut config_path = PathBuf::from("rustpp.toml");
    let mut lock_path = PathBuf::from("Cargo.lock");
    let mut index = 0;

    while index < args.len() {
        let arg = &args[index];
        if arg == "--config" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp report: --config requires a file path");
                return ExitCode::FAILURE;
            };
            config_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--config=") {
            config_path = PathBuf::from(value);
            index += 1;
        } else if arg == "--lockfile" {
            let Some(value) = args.get(index + 1) else {
                eprintln!("rpp report: --lockfile requires a file path");
                return ExitCode::FAILURE;
            };
            lock_path = PathBuf::from(value);
            index += 2;
        } else if let Some(value) = arg.strip_prefix("--lockfile=") {
            lock_path = PathBuf::from(value);
            index += 1;
        } else {
            root = PathBuf::from(arg);
            index += 1;
        }
    }

    let mut audit_report = AuditReport::default();
    if let Err(error) = collect_audit_report(&root, &mut audit_report) {
        eprintln!("rpp report: audit failed: {error}");
        return ExitCode::FAILURE;
    }

    let mut effect_findings = Vec::new();
    if let Err(error) = collect_effect_findings(&root, &mut effect_findings) {
        eprintln!("rpp report: effect scan failed: {error}");
        return ExitCode::FAILURE;
    }

    let mut contract_annotations = Vec::new();
    if let Err(error) = collect_contract_annotations(&root, &mut contract_annotations) {
        eprintln!("rpp report: contract scan failed: {error}");
        return ExitCode::FAILURE;
    }

    let packages = match fs::read_to_string(&lock_path)
        .and_then(|source| parse_cargo_lock_packages(&source))
    {
        Ok(packages) => packages,
        Err(error) => {
            eprintln!("rpp report: {}: {error}", lock_path.display());
            return ExitCode::FAILURE;
        }
    };

    let policy_violations = if config_path.exists() {
        match load_policy_config(&config_path)
            .and_then(|config| collect_policy_violations(&root, &config))
        {
            Ok(violations) => violations,
            Err(error) => {
                eprintln!("rpp report: {}: {error}", config_path.display());
                return ExitCode::FAILURE;
            }
        }
    } else {
        Vec::new()
    };

    let failed = !audit_report.unsafe_findings.is_empty()
        || !audit_report.metadata_errors.is_empty()
        || !policy_violations.is_empty();

    print_json_report(
        &root,
        &config_path,
        &lock_path,
        &audit_report,
        &effect_findings,
        &policy_violations,
        &packages,
        &contract_annotations,
        failed,
    );

    if failed {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

#[allow(clippy::too_many_arguments)]
fn print_json_report(
    root: &Path,
    config_path: &Path,
    lock_path: &Path,
    audit_report: &AuditReport,
    effect_findings: &[EffectFinding],
    policy_violations: &[PolicyViolation],
    packages: &[SbomPackage],
    contract_annotations: &[ContractAnnotation],
    failed: bool,
) {
    println!("{{");
    println!("  \"format\": \"rustpp-report-v0\",");
    println!(
        "  \"status\": \"{}\",",
        if failed { "fail" } else { "pass" }
    );
    println!(
        "  \"root\": \"{}\",",
        json_escape(&root.display().to_string())
    );
    println!(
        "  \"config\": \"{}\",",
        json_escape(&config_path.display().to_string())
    );
    println!(
        "  \"lockfile\": \"{}\",",
        json_escape(&lock_path.display().to_string())
    );
    print_json_audit_report(audit_report);
    print_json_effect_report(effect_findings);
    print_json_policy_report(policy_violations);
    print_json_contract_report(contract_annotations);
    print_json_packages(packages);
    println!("}}");
}

fn print_json_audit_report(report: &AuditReport) {
    println!("  \"audit\": {{");
    println!("    \"unsafe_findings\": [");
    for (index, finding) in report.unsafe_findings.iter().enumerate() {
        let comma = if index + 1 == report.unsafe_findings.len() {
            ""
        } else {
            ","
        };
        println!(
            "      {{ \"path\": \"{}\", \"line\": {}, \"text\": \"{}\" }}{}",
            json_escape(&finding.path.display().to_string()),
            finding.line,
            json_escape(finding.text.trim()),
            comma
        );
    }
    println!("    ],");
    println!("    \"unsafe_boundaries\": [");
    for (index, boundary) in report.boundaries.iter().enumerate() {
        let comma = if index + 1 == report.boundaries.len() {
            ""
        } else {
            ","
        };
        println!(
            "      {{ \"path\": \"{}\", \"line\": {}, \"reason\": \"{}\", \"audit\": \"{}\" }}{}",
            json_escape(&boundary.path.display().to_string()),
            boundary.line,
            json_escape(&boundary.reason),
            json_escape(&boundary.audit),
            comma
        );
    }
    println!("    ],");
    println!("    \"metadata_errors\": [");
    for (index, finding) in report.metadata_errors.iter().enumerate() {
        let comma = if index + 1 == report.metadata_errors.len() {
            ""
        } else {
            ","
        };
        println!(
            "      {{ \"path\": \"{}\", \"line\": {}, \"text\": \"{}\" }}{}",
            json_escape(&finding.path.display().to_string()),
            finding.line,
            json_escape(finding.text.trim()),
            comma
        );
    }
    println!("    ]");
    println!("  }},");
}

fn print_json_effect_report(findings: &[EffectFinding]) {
    println!("  \"effects\": [");
    for (index, finding) in findings.iter().enumerate() {
        let comma = if index + 1 == findings.len() { "" } else { "," };
        println!(
            "    {{ \"path\": \"{}\", \"line\": {}, \"effects\": [{}] }}{}",
            json_escape(&finding.path.display().to_string()),
            finding.line,
            finding
                .effects
                .iter()
                .map(|effect| format!("\"{}\"", json_escape(effect)))
                .collect::<Vec<_>>()
                .join(", "),
            comma
        );
    }
    println!("  ],");
}

fn print_json_policy_report(violations: &[PolicyViolation]) {
    println!("  \"policy\": {{");
    println!("    \"violations\": [");
    for (index, violation) in violations.iter().enumerate() {
        let comma = if index + 1 == violations.len() {
            ""
        } else {
            ","
        };
        println!(
            "      {{ \"kind\": \"{}\", \"path\": \"{}\", \"line\": {}, \"detail\": \"{}\" }}{}",
            json_escape(&violation.kind),
            json_escape(&violation.path.display().to_string()),
            violation.line,
            json_escape(&violation.detail),
            comma
        );
    }
    println!("    ]");
    println!("  }},");
}

fn print_json_packages(packages: &[SbomPackage]) {
    println!("  \"sbom\": {{");
    println!("    \"format\": \"rustpp-sbom-v0\",");
    println!("    \"packages\": [");
    for (index, package) in packages.iter().enumerate() {
        let comma = if index + 1 == packages.len() { "" } else { "," };
        println!(
            "      {{ \"name\": \"{}\", \"version\": \"{}\", \"source\": {} }}{}",
            json_escape(&package.name),
            json_escape(&package.version),
            package
                .source
                .as_ref()
                .map(|source| format!("\"{}\"", json_escape(source)))
                .unwrap_or_else(|| "null".to_string()),
            comma
        );
    }
    println!("    ]");
    println!("  }}");
}

fn print_text_sbom(packages: &[SbomPackage]) {
    println!("rustpp-sbom packages={}", packages.len());
    println!("name\tversion\tsource");
    for package in packages {
        println!(
            "{}\t{}\t{}",
            package.name,
            package.version,
            package.source.as_deref().unwrap_or("workspace")
        );
    }
}

fn print_json_sbom(packages: &[SbomPackage]) {
    println!("{{");
    println!("  \"format\": \"rustpp-sbom-v0\",");
    println!("  \"packages\": [");
    for (index, package) in packages.iter().enumerate() {
        let comma = if index + 1 == packages.len() { "" } else { "," };
        println!(
            "    {{ \"name\": \"{}\", \"version\": \"{}\", \"source\": {} }}{}",
            json_escape(&package.name),
            json_escape(&package.version),
            package
                .source
                .as_ref()
                .map(|source| format!("\"{}\"", json_escape(source)))
                .unwrap_or_else(|| "null".to_string()),
            comma
        );
    }
    println!("  ]");
    println!("}}");
}

fn parse_cargo_lock_packages(source: &str) -> io::Result<Vec<SbomPackage>> {
    let mut packages = Vec::new();
    let mut current = PartialSbomPackage::default();
    let mut in_package = false;

    for (index, line) in source.lines().enumerate() {
        let line = line.trim();
        if line == "[[package]]" {
            push_partial_package(&mut packages, &mut current, in_package, index)?;
            in_package = true;
            continue;
        }

        if !in_package {
            continue;
        }

        if let Some(value) = parse_quoted_key(line, "name") {
            current.name = Some(value.to_string());
        } else if let Some(value) = parse_quoted_key(line, "version") {
            current.version = Some(value.to_string());
        } else if let Some(value) = parse_quoted_key(line, "source") {
            current.source = Some(value.to_string());
        }
    }

    push_partial_package(
        &mut packages,
        &mut current,
        in_package,
        source.lines().count(),
    )?;
    Ok(packages)
}

fn push_partial_package(
    packages: &mut Vec<SbomPackage>,
    current: &mut PartialSbomPackage,
    should_push: bool,
    line: usize,
) -> io::Result<()> {
    if !should_push {
        return Ok(());
    }

    let name = current.name.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {line}: package is missing `name`"),
        )
    })?;
    let version = current.version.take().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {line}: package `{name}` is missing `version`"),
        )
    })?;

    packages.push(SbomPackage {
        name,
        version,
        source: current.source.take(),
    });
    Ok(())
}

fn parse_quoted_key<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    rest.strip_prefix('"')?.strip_suffix('"')
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character => escaped.push(character),
        }
    }
    escaped
}

fn enforce_policy_if_present(root: &Path, config_path: &Path) -> Result<(), CheckFailure> {
    if !config_path.exists() {
        println!(
            "rpp check: {} not found; skipping policy",
            config_path.display()
        );
        return Ok(());
    }

    match enforce_policy(root, config_path) {
        Ok(0) => {
            println!("rpp check: policy passed");
            Ok(())
        }
        Ok(violations) => {
            eprintln!("rpp check: policy failed with {violations} violation(s)");
            Err(CheckFailure::Policy(ExitCode::from(2)))
        }
        Err(error) => Err(CheckFailure::Io(error)),
    }
}

fn enforce_policy(root: &Path, config_path: &Path) -> io::Result<usize> {
    let config = load_policy_config(config_path)?;
    let violations = collect_policy_violations(root, &config)?;

    for violation in &violations {
        eprintln!(
            "rpp policy: {} at {}:{}: {}",
            violation.kind,
            violation.path.display(),
            violation.line,
            violation.detail
        );
    }

    Ok(violations.len())
}

fn collect_policy_violations(
    root: &Path,
    config: &PolicyConfig,
) -> io::Result<Vec<PolicyViolation>> {
    let mut violations = Vec::new();

    if config.deny_unsafe {
        let mut findings = Vec::new();
        collect_audit_findings(root, &mut findings)?;
        violations.extend(findings.into_iter().map(|finding| PolicyViolation {
            kind: "unsafe".to_string(),
            path: finding.path,
            line: finding.line,
            detail: finding.text.trim().to_string(),
        }));
    }

    if !config.deny_effects.is_empty() {
        let mut effect_findings = Vec::new();
        collect_effect_findings(root, &mut effect_findings)?;
        for finding in &effect_findings {
            for effect in &finding.effects {
                if config.deny_effects.iter().any(|denied| denied == effect) {
                    violations.push(PolicyViolation {
                        kind: "effect".to_string(),
                        path: finding.path.clone(),
                        line: finding.line,
                        detail: effect.clone(),
                    });
                }
            }
        }
    }

    Ok(violations)
}

fn load_policy_config(path: &Path) -> io::Result<PolicyConfig> {
    let source = fs::read_to_string(path)?;
    let mut config = PolicyConfig::default();

    for (index, line) in source.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {}: expected `key = value`", index + 1),
            ));
        };

        match key.trim() {
            "deny_unsafe" => config.deny_unsafe = parse_bool(value.trim(), index + 1)?,
            "deny_effects" => config.deny_effects = parse_string_array(value.trim(), index + 1)?,
            key => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("line {}: unknown policy key `{key}`", index + 1),
                ));
            }
        }
    }

    Ok(config)
}

fn parse_bool(value: &str, line: usize) -> io::Result<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {line}: expected boolean"),
        )),
    }
}

fn parse_string_array(value: &str, line: usize) -> io::Result<Vec<String>> {
    let Some(value) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line {line}: expected string array"),
        ));
    };

    if value.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut values = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        let Some(entry) = entry
            .strip_prefix('"')
            .and_then(|entry| entry.strip_suffix('"'))
        else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {line}: expected quoted string"),
            ));
        };

        if !is_effect_path(entry) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("line {line}: invalid effect `{entry}`"),
            ));
        }

        values.push(entry.to_string());
    }

    Ok(values)
}

fn collect_effect_findings(path: &Path, findings: &mut Vec<EffectFinding>) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_effect_findings(&entry?.path(), findings)?;
        }
        return Ok(());
    }

    if !is_source_file(path) {
        return Ok(());
    }

    let source = fs::read_to_string(path)?;
    let allow_rpp_metadata = path.extension().and_then(OsStr::to_str) == Some("rpp");
    for (index, line) in source.lines().enumerate() {
        if let Some(effects) = parse_effects_line(line, allow_rpp_metadata)? {
            findings.push(EffectFinding {
                path: path.to_path_buf(),
                line: index + 1,
                effects,
            });
        }
    }

    Ok(())
}

fn parse_effects_line(line: &str, allow_rpp_metadata: bool) -> io::Result<Option<Vec<String>>> {
    let trimmed = line.trim_start();
    let is_rust_attribute = trimmed.starts_with("#[effects");
    let is_rpp_metadata = allow_rpp_metadata && trimmed.starts_with("effects");

    if !is_rust_attribute && !is_rpp_metadata {
        return Ok(None);
    }

    let Some(open) = trimmed.find('(') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed #[effects]: missing `(`",
        ));
    };
    let Some(close) = trimmed.rfind(')') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed #[effects]: missing `)`",
        ));
    };

    if close <= open {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed #[effects]: empty delimiter range",
        ));
    }

    let effects: Vec<String> = trimmed[open + 1..close]
        .split(',')
        .map(str::trim)
        .filter(|effect| !effect.is_empty())
        .map(str::to_string)
        .collect();

    if effects.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed #[effects]: empty effect list",
        ));
    }

    if let Some(invalid) = effects.iter().find(|effect| !is_effect_path(effect)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed #[effects]: invalid effect `{invalid}`"),
        ));
    }

    Ok(Some(effects))
}

fn is_effect_path(effect: &str) -> bool {
    effect.split("::").all(is_identifier)
}

fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn collect_contract_annotations(
    path: &Path,
    annotations: &mut Vec<ContractAnnotation>,
) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            collect_contract_annotations(&entry?.path(), annotations)?;
        }
        return Ok(());
    }

    if is_source_file(path) {
        let source = fs::read_to_string(path)?;
        let allow_rpp_metadata = path.extension().and_then(OsStr::to_str) == Some("rpp");
        for (index, line) in source.lines().enumerate() {
            if let Some(mut annotation) = parse_contract_annotation_line(line, allow_rpp_metadata) {
                annotation.path = path.to_path_buf();
                annotation.line = index + 1;
                annotations.push(annotation);
            }
        }
    }

    Ok(())
}

fn parse_contract_annotation_line(
    line: &str,
    allow_rpp_metadata: bool,
) -> Option<ContractAnnotation> {
    let trimmed = line.trim_start();

    if let Some(expression) = parse_attribute_condition(trimmed, "requires") {
        return Some(contract_annotation("requires", expression, trimmed));
    }

    if let Some(expression) = parse_attribute_condition(trimmed, "ensures") {
        return Some(contract_annotation("ensures", expression, trimmed));
    }

    if let Some(expression) = parse_attribute_condition(trimmed, "invariant") {
        return Some(contract_annotation("invariant", expression, trimmed));
    }

    if is_marker_attribute(trimmed, "contract") {
        return Some(contract_annotation("contract", "", trimmed));
    }

    if !allow_rpp_metadata {
        return None;
    }

    if let Some(expression) = strip_condition(trimmed, "requires") {
        return Some(contract_annotation("requires", expression, trimmed));
    }

    if let Some(expression) = strip_condition(trimmed, "ensures") {
        return Some(contract_annotation("ensures", expression, trimmed));
    }

    if let Some(expression) = strip_condition(trimmed, "invariant") {
        return Some(contract_annotation("invariant", expression, trimmed));
    }

    if let Some(rest) = trimmed.strip_prefix("contract type ") {
        let expression = rest.trim().trim_end_matches(';').trim();
        return Some(contract_annotation("contract-type", expression, trimmed));
    }

    None
}

fn parse_attribute_condition<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix("#[")?;
    let rest = rest.strip_prefix(name)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('(')?;
    let close = rest.rfind(')')?;
    Some(rest[..close].trim())
}

fn is_marker_attribute(line: &str, name: &str) -> bool {
    line == format!("#[{name}]") || line.starts_with(&format!("#[{name}("))
}

fn contract_annotation(kind: &str, expression: &str, source: &str) -> ContractAnnotation {
    ContractAnnotation {
        path: PathBuf::new(),
        line: 0,
        kind: kind.to_string(),
        expression: expression.to_string(),
        source: source.to_string(),
    }
}

fn print_text_contract_inventory(annotations: &[ContractAnnotation]) {
    println!(
        "rpp prove: found {} contract annotation(s)",
        annotations.len()
    );

    for annotation in annotations {
        if annotation.expression.is_empty() {
            println!(
                "{}:{}: [{}] {}",
                annotation.path.display(),
                annotation.line,
                annotation.kind,
                annotation.source
            );
        } else {
            println!(
                "{}:{}: [{}] {}",
                annotation.path.display(),
                annotation.line,
                annotation.kind,
                annotation.expression
            );
        }
    }

    println!("rpp prove: static solver integration is planned after the MVP");
}

fn print_json_contract_inventory(annotations: &[ContractAnnotation]) {
    println!("{{");
    println!("  \"format\": \"rustpp-prove-v0\",");
    println!("  \"mode\": \"inventory-only\",");
    println!("  \"annotations\": [");
    print_json_contract_items(annotations, "    ");
    println!("  ]");
    println!("}}");
}

fn print_json_contract_report(annotations: &[ContractAnnotation]) {
    println!("  \"contracts\": {{");
    println!("    \"annotations\": {},", annotations.len());
    println!("    \"items\": [");
    print_json_contract_items(annotations, "      ");
    println!("    ]");
    println!("  }},");
}

fn print_json_contract_items(annotations: &[ContractAnnotation], indent: &str) {
    for (index, annotation) in annotations.iter().enumerate() {
        let comma = if index + 1 == annotations.len() {
            ""
        } else {
            ","
        };
        println!(
            "{indent}{{ \"path\": \"{}\", \"line\": {}, \"kind\": \"{}\", \"expression\": \"{}\", \"source\": \"{}\" }}{}",
            json_escape(&annotation.path.display().to_string()),
            annotation.line,
            json_escape(&annotation.kind),
            json_escape(&annotation.expression),
            json_escape(&annotation.source),
            comma
        );
    }
}

fn expand(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("rpp expand: missing source file");
        return ExitCode::FAILURE;
    };

    let path = PathBuf::from(path);
    let source = if path.extension().and_then(OsStr::to_str) == Some("rpp") {
        lower_file(&path)
    } else {
        fs::read_to_string(&path)
    };

    match source {
        Ok(source) => {
            print!("{source}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rpp expand: {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn lower(path: Option<String>) -> ExitCode {
    let Some(path) = path else {
        eprintln!("rpp lower: missing .rpp source file");
        return ExitCode::FAILURE;
    };

    let path = PathBuf::from(path);
    match lower_file(&path) {
        Ok(source) => {
            print!("{source}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rpp lower: {}: {error}", path.display());
            ExitCode::FAILURE
        }
    }
}

fn lower_file(path: &Path) -> io::Result<String> {
    let source = fs::read_to_string(path)?;
    Ok(lower_source(&source))
}

fn lower_source(source: &str) -> String {
    let mut lowered = String::new();
    let mut delayed_function: Option<DelayedFunction> = None;

    for line in source.lines() {
        if let Some(function) = delayed_function.as_mut() {
            if let Some(attribute) = lower_metadata_line(line, &function.indent) {
                function.attributes.push(attribute);
                continue;
            }

            let function = delayed_function
                .take()
                .expect("delayed function should exist");
            if line.trim_start().starts_with('{') {
                flush_delayed_function(&mut lowered, function, Some(line));
                continue;
            }

            flush_delayed_function(&mut lowered, function, None);
        }

        if let Some(function) = delayed_function_from_line(line) {
            delayed_function = Some(function);
            continue;
        }

        lowered.push_str(&lower_line(line));
        lowered.push('\n');
    }

    if let Some(function) = delayed_function {
        flush_delayed_function(&mut lowered, function, None);
    }

    lowered
}

fn lower_line(line: &str) -> String {
    lower_contract_type_line(line)
        .or_else(|| lower_leading_keyword(line, "component", "struct"))
        .or_else(|| lower_leading_keyword(line, "protocol", "trait"))
        .or_else(|| lower_metadata_line(line, line_indent(line)))
        .unwrap_or_else(|| line.to_string())
}

fn lower_contract_type_line(line: &str) -> Option<String> {
    let indent = line_indent(line);
    let rest = line[indent.len()..].trim_end();
    let rest = rest.strip_prefix("contract type ")?;
    let rest = rest.strip_suffix(';').unwrap_or(rest).trim();
    let (name, rest) = rest.split_once('=')?;
    let (inner, predicate) = rest.split_once(" where ")?;
    let name = name.trim();
    let inner = inner.trim();
    let predicate = predicate.trim();

    if !is_identifier(name) || inner.is_empty() || !predicate.starts_with('|') {
        return None;
    }

    Some(format!(
        "{indent}refined_type! {{\n{indent}    struct {name}({inner}) where {predicate};\n{indent}}}"
    ))
}

fn delayed_function_from_line(line: &str) -> Option<DelayedFunction> {
    let trimmed = line.trim_start();
    if trimmed.ends_with(';') || trimmed.contains('{') || !looks_like_function_signature(trimmed) {
        return None;
    }

    Some(DelayedFunction {
        indent: line_indent(line).to_string(),
        signature: line.to_string(),
        attributes: Vec::new(),
    })
}

fn looks_like_function_signature(trimmed: &str) -> bool {
    trimmed.starts_with("fn ")
        || trimmed.starts_with("async fn ")
        || trimmed.contains(" fn ")
        || trimmed.contains(" fn<")
}

fn lower_metadata_line(line: &str, target_indent: &str) -> Option<String> {
    let trimmed = line.trim_start();

    if let Some(args) = strip_call(trimmed, "effects") {
        return Some(format!("{target_indent}#[effects({args})]"));
    }

    if let Some(condition) = strip_condition(trimmed, "requires") {
        return Some(format!("{target_indent}#[requires({condition})]"));
    }

    if let Some(condition) = strip_condition(trimmed, "ensures") {
        return Some(format!("{target_indent}#[ensures({condition})]"));
    }

    None
}

fn strip_call<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('(')?;
    let rest = rest.strip_suffix(')')?;
    Some(rest.trim())
}

fn strip_condition<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    if let Some(args) = strip_call(line, keyword) {
        return Some(args);
    }

    line.strip_prefix(keyword)
        .map(str::trim_start)
        .filter(|condition| !condition.is_empty())
}

fn line_indent(line: &str) -> &str {
    let indent_len = line.len() - line.trim_start().len();
    &line[..indent_len]
}

fn flush_delayed_function(
    lowered: &mut String,
    function: DelayedFunction,
    opening_line: Option<&str>,
) {
    for attribute in function.attributes {
        lowered.push_str(&attribute);
        lowered.push('\n');
    }

    lowered.push_str(&function.signature);
    if let Some(opening_line) = opening_line {
        let opening = opening_line.trim_start();
        if let Some(rest) = opening.strip_prefix('{') {
            lowered.push_str(" {");
            lowered.push_str(rest);
            lowered.push('\n');
            return;
        }
    }

    lowered.push('\n');
}

fn lower_leading_keyword(line: &str, from: &str, to: &str) -> Option<String> {
    let indent = line_indent(line);
    let rest = &line[indent.len()..];
    let after_keyword = rest.strip_prefix(from)?;

    if !after_keyword
        .chars()
        .next()
        .is_some_and(char::is_whitespace)
    {
        return None;
    }

    Some(format!("{indent}{to}{after_keyword}"))
}

fn create_project(name: &str) -> ExitCode {
    let root = PathBuf::from(name);
    if root.exists() {
        eprintln!("rpp new: {name} already exists");
        return ExitCode::FAILURE;
    }

    let package_name = match package_name_from_path(&root) {
        Some(package_name) => package_name,
        None => {
            eprintln!("rpp new: invalid project name `{name}`");
            return ExitCode::FAILURE;
        }
    };

    let src = root.join("src");
    if let Err(error) = fs::create_dir_all(&src) {
        eprintln!("rpp new: {error}");
        return ExitCode::FAILURE;
    }

    let manifest = format!(
        "[package]\nname = \"{package_name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\nstdpp = {{ path = \"../crates/stdpp\" }}\n"
    );
    let main_rs = "use stdpp::prelude::*;\n\n#[component]\nstruct App;\n\n#[contract]\nimpl App {\n    #[requires(value > 0)]\n    fn double(&self, value: i32) -> i32 {\n        value * 2\n    }\n}\n\nfn main() {\n    let app = App;\n    println!(\"{}\", app.double(21));\n}\n";
    let policy = "[policy]\ndeny_unsafe = true\ndeny_effects = [\"Net\"]\n";

    if let Err(error) = fs::write(root.join("Cargo.toml"), manifest) {
        eprintln!("rpp new: {error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = fs::write(src.join("main.rs"), main_rs) {
        eprintln!("rpp new: {error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = fs::write(root.join("rustpp.toml"), policy) {
        eprintln!("rpp new: {error}");
        return ExitCode::FAILURE;
    }

    println!("created Rust++ MVP project `{name}`");
    ExitCode::SUCCESS
}

fn package_name_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if name.is_empty() {
        return None;
    }

    let normalized = name.replace('_', "-");
    if normalized
        .chars()
        .all(|character| character == '-' || character.is_ascii_alphanumeric())
    {
        Some(normalized)
    } else {
        None
    }
}

struct Finding {
    path: PathBuf,
    line: usize,
    text: String,
}

#[derive(Default)]
struct AuditReport {
    unsafe_findings: Vec<Finding>,
    boundaries: Vec<UnsafeBoundaryFinding>,
    metadata_errors: Vec<Finding>,
}

struct UnsafeBoundaryFinding {
    path: PathBuf,
    line: usize,
    reason: String,
    audit: String,
}

struct PolicyViolation {
    kind: String,
    path: PathBuf,
    line: usize,
    detail: String,
}

#[derive(Debug, Eq, PartialEq)]
struct MigrationFinding {
    path: PathBuf,
    line: usize,
    kind: String,
    detail: String,
    suggestion: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ContractAnnotation {
    path: PathBuf,
    line: usize,
    kind: String,
    expression: String,
    source: String,
}

struct CiConfig {
    root: PathBuf,
    config_path: PathBuf,
    lock_path: PathBuf,
    report_path: Option<PathBuf>,
}

struct EffectFinding {
    path: PathBuf,
    line: usize,
    effects: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct SbomPackage {
    name: String,
    version: String,
    source: Option<String>,
}

#[derive(Default)]
struct PartialSbomPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
}

struct DelayedFunction {
    indent: String,
    signature: String,
    attributes: Vec<String>,
}

enum CheckFailure {
    Policy(ExitCode),
    Io(io::Error),
}

#[derive(Default)]
struct PolicyConfig {
    deny_unsafe: bool,
    deny_effects: Vec<String>,
}

fn contains_unsafe_keyword(line: &str) -> bool {
    let mut in_string = false;
    let mut escaped = false;
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;

    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();

        if !in_string && current == '/' && next == Some('/') {
            break;
        }

        if current == '"' && !escaped {
            in_string = !in_string;
            index += 1;
            continue;
        }

        if in_string {
            escaped = current == '\\' && !escaped;
            if current != '\\' {
                escaped = false;
            }
            index += 1;
            continue;
        }

        if starts_with_keyword(&chars, index, "unsafe") {
            return true;
        }

        index += 1;
    }

    false
}

fn starts_with_keyword(chars: &[char], index: usize, keyword: &str) -> bool {
    let keyword_chars: Vec<char> = keyword.chars().collect();
    if chars.len() < index + keyword_chars.len() {
        return false;
    }

    if chars[index..index + keyword_chars.len()] != keyword_chars {
        return false;
    }

    let before = index.checked_sub(1).and_then(|before| chars.get(before));
    let after = chars.get(index + keyword_chars.len());

    !before.is_some_and(|character| is_identifier_char(*character))
        && !after.is_some_and(|character| is_identifier_char(*character))
}

fn is_identifier_char(character: char) -> bool {
    character == '_' || character.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_effect_annotations() {
        let effects = parse_effects_line("    #[effects(Db, Time)]", false)
            .unwrap()
            .expect("effects should parse");

        assert_eq!(effects, ["Db", "Time"]);
    }

    #[test]
    fn parses_rpp_effect_annotations() {
        let effects = parse_effects_line("    effects(Db, Time)", true)
            .unwrap()
            .expect("effects should parse");

        assert_eq!(effects, ["Db", "Time"]);
    }

    #[test]
    fn rejects_invalid_effect_names() {
        let error = parse_effects_line("#[effects(Db, 1Net)]", false).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn ignores_rpp_effect_calls_in_rust_sources() {
        assert!(
            parse_effects_line("effects(args.collect()),", false)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn detects_unsafe_keyword_without_identifier_noise() {
        assert!(contains_unsafe_keyword("unsafe { call() }"));
        assert!(!contains_unsafe_keyword("fn unsafe_boundary() {}"));
        assert!(!contains_unsafe_keyword("\"unsafe\""));
        assert!(!contains_unsafe_keyword("// unsafe"));
    }

    #[test]
    fn parses_unsafe_boundary_metadata() {
        assert_eq!(
            parse_unsafe_boundary_line(r#"#[unsafe_boundary(reason = "FFI", audit = "2026-04")]"#),
            Some(Ok(("FFI".to_string(), "2026-04".to_string())))
        );

        assert!(
            parse_unsafe_boundary_line(r#"#[unsafe_boundary(reason = "FFI")]"#)
                .expect("boundary should be recognized")
                .is_err()
        );
    }

    #[test]
    fn lowers_component_and_protocol_preview_syntax() {
        let source = "contract type PositiveMoney = i64 where |value| *value > 0;\n\nprotocol Repo {\n    fn len(&self) -> usize;\n}\n\ncomponent Service<R: Repo> {\n    repo: R,\n}\n";

        assert_eq!(
            lower_source(source),
            "refined_type! {\n    struct PositiveMoney(i64) where |value| *value > 0;\n}\n\ntrait Repo {\n    fn len(&self) -> usize;\n}\n\nstruct Service<R: Repo> {\n    repo: R,\n}\n"
        );
    }

    #[test]
    fn lowers_postfix_metadata_to_attributes() {
        let source = "async fn charge(amount: i64) -> Result<u64>\n    effects(Db, Time)\n    requires amount > 0\n    ensures result.is_ok()\n{\n    Ok(amount as u64)\n}\n";

        assert_eq!(
            lower_source(source),
            "#[effects(Db, Time)]\n#[requires(amount > 0)]\n#[ensures(result.is_ok())]\nasync fn charge(amount: i64) -> Result<u64> {\n    Ok(amount as u64)\n}\n"
        );
    }

    #[test]
    fn parses_policy_arrays() {
        assert_eq!(
            parse_string_array("[\"Net\", \"Db\"]", 1).unwrap(),
            ["Net", "Db"]
        );
    }

    #[test]
    fn detects_migration_candidates() {
        let mut findings = Vec::new();
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            1,
            "type Money = i64;",
            &[],
            false,
            &mut findings,
        );
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            2,
            "async fn charge(amount: i64) -> Result<u64>",
            &[],
            false,
            &mut findings,
        );
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            3,
            "struct Service {",
            &[],
            false,
            &mut findings,
        );

        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "refinement-type")
        );
        assert!(findings.iter().any(|finding| finding.kind == "effect"));
        assert!(findings.iter().any(|finding| finding.kind == "component"));
        assert!(
            findings
                .iter()
                .any(|finding| finding.kind == "refinement-parameter")
        );
    }

    #[test]
    fn migration_respects_existing_effect_attribute() {
        let mut findings = Vec::new();
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            1,
            "async fn charge(amount: i64) -> Result<u64>",
            &["#[effects(Db)]".to_string()],
            false,
            &mut findings,
        );

        assert!(!findings.iter().any(|finding| finding.kind == "effect"));
    }

    #[test]
    fn migration_ignores_refined_type_macro_body() {
        let mut findings = Vec::new();
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            1,
            "    struct PositiveMoney(Money) where |value| *value > 0;",
            &[],
            true,
            &mut findings,
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn migration_ignores_tuple_struct_components() {
        let mut findings = Vec::new();
        collect_migration_line_findings(
            Path::new("src/lib.rs"),
            1,
            "struct PaymentError(&'static str);",
            &[],
            false,
            &mut findings,
        );

        assert!(!findings.iter().any(|finding| finding.kind == "component"));
    }

    #[test]
    fn parses_ci_args() {
        let config = parse_ci_args(vec![
            "--root".to_string(),
            "src".to_string(),
            "--config=policy.toml".to_string(),
            "--lockfile".to_string(),
            "Lock.toml".to_string(),
            "--report".to_string(),
            "report.json".to_string(),
        ])
        .unwrap();

        assert_eq!(config.root, PathBuf::from("src"));
        assert_eq!(config.config_path, PathBuf::from("policy.toml"));
        assert_eq!(config.lock_path, PathBuf::from("Lock.toml"));
        assert_eq!(config.report_path, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn parses_cargo_lock_packages_for_sbom() {
        let source = r#"
version = 4

[[package]]
name = "demo"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

        assert_eq!(
            parse_cargo_lock_packages(source).unwrap(),
            [
                SbomPackage {
                    name: "demo".to_string(),
                    version: "0.1.0".to_string(),
                    source: None,
                },
                SbomPackage {
                    name: "serde".to_string(),
                    version: "1.0.0".to_string(),
                    source: Some(
                        "registry+https://github.com/rust-lang/crates.io-index".to_string()
                    ),
                },
            ]
        );
    }

    #[test]
    fn parses_rpp_contract_annotations() {
        assert_eq!(
            parse_contract_annotation_line(
                "contract type PositiveMoney = i64 where |value| *value > 0;",
                true
            )
            .unwrap()
            .kind,
            "contract-type"
        );
        assert_eq!(
            parse_contract_annotation_line("    requires amount > 0", true)
                .unwrap()
                .expression,
            "amount > 0"
        );
        assert_eq!(
            parse_contract_annotation_line("    ensures(result.is_ok())", true)
                .unwrap()
                .expression,
            "result.is_ok()"
        );
        assert!(parse_contract_annotation_line("    requires amount > 0", false).is_none());
    }

    #[test]
    fn parses_rust_contract_attributes() {
        assert_eq!(
            parse_contract_annotation_line("#[requires(value > 0)]", false)
                .unwrap()
                .expression,
            "value > 0"
        );
        assert_eq!(
            parse_contract_annotation_line("#[ensures(result.is_ok())]", false)
                .unwrap()
                .kind,
            "ensures"
        );
        assert_eq!(
            parse_contract_annotation_line("#[contract]", false)
                .unwrap()
                .kind,
            "contract"
        );
        assert!(parse_contract_annotation_line("#[contractual]", false).is_none());
        assert!(parse_contract_annotation_line("#[component]", false).is_none());
    }

    #[test]
    fn inventories_contract_annotations_from_file() {
        let root = env::temp_dir().join(format!("rustpp-contract-test-{}", std::process::id()));
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(
            src.join("lib.rs"),
            "#[contract]\nimpl App {\n    #[requires(value > 0)]\n    fn double(value: i32) -> i32 { value * 2 }\n}\n",
        )
        .unwrap();

        let mut annotations = Vec::new();
        collect_contract_annotations(&root, &mut annotations).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(annotations.len(), 2);
        assert!(
            annotations
                .iter()
                .any(|annotation| annotation.kind == "contract")
        );
        assert!(
            annotations
                .iter()
                .any(|annotation| annotation.expression == "value > 0")
        );
    }

    #[test]
    fn legacy_rpp_contract_examples_still_match() {
        assert!(
            parse_contract_annotation_line(
                "contract type PositiveMoney = i64 where |value| *value > 0;",
                true
            )
            .is_some()
        );
        assert!(parse_contract_annotation_line("    requires amount > 0", true).is_some());
        assert!(parse_contract_annotation_line("    ensures(result.is_ok())", true).is_some());
        assert!(parse_contract_annotation_line("    requires amount > 0", false).is_none());
    }

    #[test]
    fn derives_package_name_from_path() {
        assert_eq!(
            package_name_from_path(Path::new("/tmp/my_app")).unwrap(),
            "my-app"
        );
        assert!(package_name_from_path(Path::new("bad/name!")).is_none());
    }
}
