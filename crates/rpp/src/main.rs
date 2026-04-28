use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

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
        "check" => rpp_check(args.collect()),
        "test" => run_cargo("test", args.collect()),
        "build" => run_cargo("build", args.collect()),
        "effects" => effects(args.collect()),
        "policy" => policy(args.collect()),
        "sbom" => sbom(args.collect()),
        "prove" => prove(args.next().unwrap_or_else(|| ".".to_string())),
        "lower" => lower(args.next()),
        "expand" => expand(args.next()),
        "new" => match args.next() {
            Some(name) => create_project(&name),
            None => {
                eprintln!("rpp new: missing project name");
                ExitCode::FAILURE
            }
        },
        "migrate" => {
            println!("rpp migrate: scan-only migration is not implemented yet");
            ExitCode::SUCCESS
        }
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
        "Rust++ MVP tooling\n\nUSAGE:\n    rpp <command>\n\nCOMMANDS:\n    new <name>                  Create a Rust++ MVP project\n    check [--no-policy] [args]  Enforce policy, then run cargo check\n    test [args...]              Run cargo test\n    build [args...]             Run cargo build\n    audit [path]                Report unsafe usage and unsafe boundaries\n    effects [--deny A,B] [path] Report and optionally deny effects\n    policy [--config F] [path]  Enforce rustpp.toml policy\n    sbom [--json] [Cargo.lock]  Emit a minimal dependency SBOM\n    prove [path]                Count contract annotations\n    lower <file.rpp>            Lower Rust++ syntax preview to Rust\n    expand <file>               Print the current lowering view\n"
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

fn prove(root: String) -> ExitCode {
    let root = Path::new(&root);
    let mut count = 0usize;

    match count_contract_annotations(root, &mut count) {
        Ok(()) => {
            println!("rpp prove: found {count} contract annotation(s)");
            println!("rpp prove: static solver integration is planned after the MVP");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("rpp prove: {error}");
            ExitCode::FAILURE
        }
    }
}

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
    let mut violations = 0usize;

    if config.deny_unsafe {
        let mut findings = Vec::new();
        collect_audit_findings(root, &mut findings)?;
        if !findings.is_empty() {
            violations += findings.len();
            eprintln!("rpp policy: unsafe usage denied");
            for finding in findings {
                eprintln!(
                    "{}:{}: {}",
                    finding.path.display(),
                    finding.line,
                    finding.text.trim()
                );
            }
        }
    }

    let mut effect_findings = Vec::new();
    collect_effect_findings(root, &mut effect_findings)?;
    for finding in &effect_findings {
        for effect in &finding.effects {
            if config.deny_effects.iter().any(|denied| denied == effect) {
                violations += 1;
                eprintln!(
                    "rpp policy: denied effect `{effect}` at {}:{}",
                    finding.path.display(),
                    finding.line
                );
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

fn count_contract_annotations(path: &Path, count: &mut usize) -> io::Result<()> {
    if should_skip(path) {
        return Ok(());
    }

    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            count_contract_annotations(&entry?.path(), count)?;
        }
        return Ok(());
    }

    if is_source_file(path) {
        let source = fs::read_to_string(path)?;
        let allow_rpp_metadata = path.extension().and_then(OsStr::to_str) == Some("rpp");
        for line in source.lines() {
            if is_contract_annotation_line(line, allow_rpp_metadata) {
                *count += 1;
            }
        }
    }

    Ok(())
}

fn is_contract_annotation_line(line: &str, allow_rpp_metadata: bool) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("#[requires")
        || trimmed.starts_with("#[ensures")
        || trimmed.starts_with("#[contract")
        || (allow_rpp_metadata
            && (trimmed.starts_with("requires ")
                || trimmed.starts_with("requires(")
                || trimmed.starts_with("ensures ")
                || trimmed.starts_with("ensures(")
                || trimmed.starts_with("contract type ")))
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
    fn counts_rpp_contract_annotations() {
        assert!(is_contract_annotation_line(
            "contract type PositiveMoney = i64 where |value| *value > 0;",
            true
        ));
        assert!(is_contract_annotation_line("    requires amount > 0", true));
        assert!(is_contract_annotation_line(
            "    ensures(result.is_ok())",
            true
        ));
        assert!(!is_contract_annotation_line(
            "    requires amount > 0",
            false
        ));
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
