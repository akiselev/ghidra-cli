//! Cross-platform JDK detection and validation.
//!
//! Ghidra compiles GhidraScript `.java` files at runtime via the OSGi
//! `GhidraSourceBundle`, which calls `javax.tools.ToolProvider.getSystemJavaCompiler()`.
//! That returns `null` on a JRE (or a `jlink`-trimmed image) because the
//! `jdk.compiler` module is absent. So Ghidra needs a *full JDK*, not just a JRE,
//! and the on-disk `javac` binary alone is not the whole story.
//!
//! A valid JDK for our purposes therefore requires all of:
//!   1. a `javac` executable next to `java`,
//!   2. the `jdk.compiler` module present (`java --list-modules`),
//!   3. major version >= Ghidra's required minimum (read from the install).
//!
//! We resolve the Java that *we* will hand to Ghidra (via `JAVA_HOME` on the
//! `analyzeHeadless` child process) rather than relying on Ghidra's own
//! PATH-based auto-pick, which lands on whatever `java` is first on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The default Java floor if we cannot read it from the Ghidra install.
/// Ghidra 12.x sets `application.java.min=21`.
pub const DEFAULT_MIN_JAVA: u32 = 21;

/// Details about a validated JDK.
#[derive(Debug, Clone)]
pub struct JdkInfo {
    pub home: PathBuf,
    pub major: u32,
    /// How this JDK was selected (for diagnostics).
    pub source: String,
}

/// Outcome of inspecting a single Java home.
#[derive(Debug, Clone)]
pub enum JavaStatus {
    /// A usable full JDK.
    Ok(JdkInfo),
    /// Right version, but it's a JRE / has no compiler (no javac or no jdk.compiler).
    JreNoCompiler { home: PathBuf, major: u32 },
    /// A JDK, but the version is below the required minimum.
    WrongVersion { home: PathBuf, major: u32, min: u32 },
    /// No Java found at all.
    NotFound,
}

fn exe(base: &str) -> String {
    #[cfg(windows)]
    {
        format!("{base}.exe")
    }
    #[cfg(not(windows))]
    {
        base.to_string()
    }
}

/// `<home>/bin/<name>[.exe]`
fn bin(home: &Path, name: &str) -> PathBuf {
    home.join("bin").join(exe(name))
}

/// Derive a Java home from a `java` executable path (`.../bin/java` -> `...`).
fn home_from_java_exe(java_exe: &Path) -> Option<PathBuf> {
    java_exe.parent()?.parent().map(|p| p.to_path_buf())
}

/// Parse the major version from `java -version` output (goes to stderr).
fn detect_major(java_exe: &Path) -> Option<u32> {
    let out = Command::new(java_exe).arg("-version").output().ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    // Matches `version "21"`, `version "21.0.3"`, `version "1.8.0_xxx"` (-> 8).
    let re = regex::Regex::new(r#"version "(\d+)(?:\.(\d+))?"#).ok()?;
    let caps = re.captures(&text)?;
    let first: u32 = caps.get(1)?.as_str().parse().ok()?;
    if first == 1 {
        // Legacy "1.8" style -> the real major is the second component.
        caps.get(2)?.as_str().parse().ok()
    } else {
        Some(first)
    }
}

/// Does this runtime have the `jdk.compiler` module (the actual `javac`
/// implementation that backs `getSystemJavaCompiler()`)?
fn has_jdk_compiler_module(java_exe: &Path) -> bool {
    match Command::new(java_exe).arg("--list-modules").output() {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .any(|l| l.starts_with("jdk.compiler@") || l == "jdk.compiler")
        }
        Err(_) => false,
    }
}

/// Inspect a single Java home and classify it.
pub fn inspect_home(home: &Path, min: u32, source: &str) -> JavaStatus {
    let java_exe = bin(home, "java");
    if !java_exe.exists() {
        return JavaStatus::NotFound;
    }
    let major = match detect_major(&java_exe) {
        Some(m) => m,
        None => return JavaStatus::NotFound,
    };

    let javac = bin(home, "javac");
    let has_compiler = javac.exists() && has_jdk_compiler_module(&java_exe);

    if !has_compiler {
        return JavaStatus::JreNoCompiler {
            home: home.to_path_buf(),
            major,
        };
    }
    if major < min {
        return JavaStatus::WrongVersion {
            home: home.to_path_buf(),
            major,
            min,
        };
    }
    JavaStatus::Ok(JdkInfo {
        home: home.to_path_buf(),
        major,
        source: source.to_string(),
    })
}

/// Candidate (home, source-label) pairs, in priority order.
fn candidate_homes(explicit: Option<&Path>) -> Vec<(PathBuf, String)> {
    let mut out: Vec<(PathBuf, String)> = Vec::new();
    let mut push = |home: PathBuf, src: &str| {
        if !out.iter().any(|(h, _)| h == &home) {
            out.push((home, src.to_string()));
        }
    };

    // 1. Explicit (flag / env / config), already folded into `explicit` by caller.
    if let Some(p) = explicit {
        push(
            p.to_path_buf(),
            "explicit (--java-home / GHIDRA_CLI_JAVA_HOME / config)",
        );
    }
    // 2. JAVA_HOME environment variable.
    if let Ok(jh) = std::env::var("JAVA_HOME") {
        if !jh.is_empty() {
            push(PathBuf::from(jh), "JAVA_HOME");
        }
    }
    // 3. The `java` on PATH -> its home.
    if let Ok(java_exe) = which::which("java") {
        let real = std::fs::canonicalize(&java_exe).unwrap_or(java_exe);
        if let Some(home) = home_from_java_exe(&real) {
            push(home, "PATH java");
        }
    }
    // 4. Per-OS scan of common JDK install roots (prefer higher versions).
    for (home, src) in scan_install_roots() {
        push(home, &src);
    }
    out
}

/// Scan well-known install locations and return candidate homes, newest-looking first.
fn scan_install_roots() -> Vec<(PathBuf, String)> {
    let mut roots: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    {
        roots.push(PathBuf::from("/usr/lib/jvm"));
        roots.push(PathBuf::from("/usr/java"));
    }
    #[cfg(target_os = "macos")]
    {
        roots.push(PathBuf::from("/Library/Java/JavaVirtualMachines"));
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join("Library/Java/JavaVirtualMachines"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        roots.push(PathBuf::from(r"C:\Program Files\Java"));
        roots.push(PathBuf::from(r"C:\Program Files\Eclipse Adoptium"));
        roots.push(PathBuf::from(r"C:\Program Files\Microsoft"));
    }

    let mut found: Vec<PathBuf> = Vec::new();
    for root in roots {
        if let Ok(entries) = std::fs::read_dir(&root) {
            for e in entries.flatten() {
                let mut p = e.path();
                if !p.is_dir() {
                    continue;
                }
                // macOS bundles nest the home under Contents/Home.
                let macos_home = p.join("Contents/Home");
                if macos_home.join("bin").exists() {
                    p = macos_home;
                }
                if p.join("bin").exists() {
                    found.push(p);
                }
            }
        }
    }
    // Sort descending by directory name so newer versions (e.g. java-21 > java-17)
    // are tried before older ones.
    found.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    found
        .into_iter()
        .map(|p| (p, "system scan".to_string()))
        .collect()
}

/// Read Ghidra's required minimum Java major version from the install
/// (`<install>/Ghidra/application.properties`, `application.java.min`).
/// Falls back to [`DEFAULT_MIN_JAVA`].
pub fn ghidra_min_java(install_dir: &Path) -> u32 {
    let props = install_dir.join("Ghidra").join("application.properties");
    if let Ok(text) = std::fs::read_to_string(&props) {
        for line in text.lines() {
            if let Some(val) = line.trim().strip_prefix("application.java.min=") {
                if let Ok(v) = val.trim().parse::<u32>() {
                    return v;
                }
            }
        }
    }
    DEFAULT_MIN_JAVA
}

/// Resolve the best JDK to use, given an optional explicit home and a minimum
/// major version. Returns the first usable JDK, or the most informative failure.
pub fn resolve_jdk(explicit: Option<&Path>, min: u32) -> JavaStatus {
    let mut best_failure = JavaStatus::NotFound;
    for (home, source) in candidate_homes(explicit) {
        match inspect_home(&home, min, &source) {
            JavaStatus::Ok(info) => return JavaStatus::Ok(info),
            // Keep the most specific failure to report if nothing works:
            // WrongVersion (a real JDK, just old) > JreNoCompiler > NotFound.
            other => {
                best_failure = pick_better_failure(best_failure, other);
            }
        }
    }
    best_failure
}

fn rank(s: &JavaStatus) -> u8 {
    match s {
        JavaStatus::Ok(_) => 3,
        JavaStatus::WrongVersion { .. } => 2,
        JavaStatus::JreNoCompiler { .. } => 1,
        JavaStatus::NotFound => 0,
    }
}

fn pick_better_failure(a: JavaStatus, b: JavaStatus) -> JavaStatus {
    if rank(&b) > rank(&a) {
        b
    } else {
        a
    }
}

/// Human-readable explanation of a non-`Ok` [`JavaStatus`].
pub fn describe_failure(status: &JavaStatus) -> String {
    match status {
        JavaStatus::Ok(info) => format!("JDK {} at {}", info.major, info.home.display()),
        JavaStatus::JreNoCompiler { home, major } => format!(
            "Java {major} at {} is a JRE (no javac / jdk.compiler). Ghidra needs a full JDK.",
            home.display()
        ),
        JavaStatus::WrongVersion { home, major, min } => format!(
            "JDK {major} at {} is below the required JDK {min}+.",
            home.display()
        ),
        JavaStatus::NotFound => "No Java found on PATH or in common JDK locations.".to_string(),
    }
}

/// Convenience: resolve the JDK for a given Ghidra install, folding in the
/// explicit override from env/config. Returns `Ok(JdkInfo)` or a human-readable
/// error describing exactly what's wrong and how to fix it.
pub fn resolve_for_ghidra(
    install_dir: &Path,
    explicit: Option<PathBuf>,
) -> std::result::Result<JdkInfo, String> {
    let min = ghidra_min_java(install_dir);
    match resolve_jdk(explicit.as_deref(), min) {
        JavaStatus::Ok(info) => Ok(info),
        JavaStatus::JreNoCompiler { home, major } => Err(format!(
            "Found Java {major} at {} but it is a JRE (no `javac` / `jdk.compiler` module).\n\
             Ghidra compiles scripts at runtime and requires a full JDK {min}+, not a JRE.\n\
             Fix: install a JDK (Linux: apt install openjdk-{min}-jdk / dnf install java-{min}-openjdk-devel;\n\
             macOS: brew install openjdk@{min}; Windows: install Temurin/Corretto JDK {min}+),\n\
             or point ghidra-cli at one with --java-home, GHIDRA_CLI_JAVA_HOME, or config `java_home`.",
            home.display()
        )),
        JavaStatus::WrongVersion { home, major, min } => Err(format!(
            "Found JDK {major} at {} but Ghidra requires JDK {min}+.\n\
             Install a newer JDK or select one with --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`.",
            home.display()
        )),
        JavaStatus::NotFound => Err(format!(
            "No Java found. Ghidra requires a full JDK {min}+.\n\
             Install a JDK and ensure it is on PATH, or set --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`."
        )),
    }
}
