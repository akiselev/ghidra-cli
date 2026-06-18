mod cli;
mod config;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;

use clap::Parser;
use cli::{Cli, Commands, QueryOptions};
use config::Config;
use error::GhidraError;
use format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use ghidra::bridge::{self, BridgeStartMode, BridgeStatus};
use ghidra::GhidraClient;
use ipc::client::BridgeClient;
use query::Query;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    let cli = Cli::parse();

    // Fold the global --java-home flag into an env var so config and the bridge
    // launcher pick it up without threading it through every call site.
    if let Some(jh) = &cli.java_home {
        std::env::set_var("GHIDRA_CLI_JAVA_HOME", jh);
    }

    // --- Logging setup ---
    // File layer: always writes at debug level
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("ghidra-cli");
    let _ = std::fs::create_dir_all(&log_dir);
    let file_appender = tracing_appender::rolling::daily(&log_dir, "ghidra-cli.log");
    let file_layer = tracing_subscriber::fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false)
        .with_filter(tracing_subscriber::EnvFilter::new("debug"));

    // Stdout layer: only if -v/-vv/-vvv is specified
    let stdout_layer = match cli.verbose {
        1 => Some("warn"),
        2 => Some("info"),
        3.. => Some("debug"),
        _ => None,
    }
    .map(|level| {
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
            )
    });

    tracing_subscriber::registry()
        .with(file_layer)
        .with(stdout_layer)
        .init();

    let result = match &cli.command {
        Commands::Setup(_) => {
            // Setup needs async for downloading
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(run_setup(cli))
        }
        Commands::Start { .. }
        | Commands::Stop { .. }
        | Commands::Restart { .. }
        | Commands::Status { .. }
        | Commands::Ping { .. } => handle_bridge_command(cli),
        _ => run_command(cli),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

/// Run a command, starting the bridge if needed.
fn run_command(cli: Cli) -> anyhow::Result<()> {
    match &cli.command {
        // Non-bridge commands
        Commands::Init => handle_init(),
        Commands::Doctor => handle_doctor(),
        Commands::Version => handle_version(),
        Commands::Config(cmd) => handle_config_command(cmd.clone()),
        Commands::SetDefault(args) => handle_set_default(args.clone()),
        Commands::Project(args) => handle_project_command(args.command.clone()),
        // Commands requiring bridge
        _ if requires_bridge(&cli.command) => run_with_bridge(cli),
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Determines if a command requires the bridge to be running.
fn requires_bridge(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Import(_)
            | Commands::Analyze(_)
            | Commands::Query(_)
            | Commands::Decompile(_)
            | Commands::Function(_)
            | Commands::Strings(_)
            | Commands::Memory(_)
            | Commands::Dump(_)
            | Commands::Summary(_)
            | Commands::XRef(_)
            | Commands::Symbol(_)
            | Commands::Type(_)
            | Commands::Comment(_)
            | Commands::Graph(_)
            | Commands::Find(_)
            | Commands::Diff(_)
            | Commands::Patch(_)
            | Commands::Script(_)
            | Commands::Disasm(_)
            | Commands::Batch(_)
            | Commands::Stats(_)
            | Commands::Program(_)
            | Commands::Rename(_)
    )
}

/// Extract the project name from a command's args (if present).
fn extract_project_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Import(args) => args.project.clone(),
        Commands::Analyze(args) => args.project.clone(),
        Commands::Query(args) => args.project.clone(),
        Commands::Summary(args) => args.options.project.clone(),
        Commands::Decompile(args) => args.options.project.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(opts) => opts.project.clone(),
            cli::FunctionCommands::Decompile(args) => args.options.project.clone(),
            cli::FunctionCommands::Get(args) => args.options.project.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.project.clone(),
            cli::FunctionCommands::Calls(args) => args.options.project.clone(),
            cli::FunctionCommands::XRefs(args) => args.options.project.clone(),
            cli::FunctionCommands::Rename(args) => args.project.clone(),
            cli::FunctionCommands::Create(args) => args.project.clone(),
            cli::FunctionCommands::Delete(args) => args.options.project.clone(),
            cli::FunctionCommands::SetSignature(args) => args.project.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.project.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.project.clone(),
            cli::FunctionCommands::SetVarType(args) => args.project.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.project.clone(),
            cli::StringsCommands::Refs(args) => args.options.project.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.project.clone(),
            cli::MemoryCommands::Read(args) => args.options.project.clone(),
            cli::MemoryCommands::Write(args) => args.project.clone(),
            cli::MemoryCommands::Search(args) => args.options.project.clone(),
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => opts.project.clone(),
            cli::DumpCommands::Exports(opts) => opts.project.clone(),
            cli::DumpCommands::Functions(opts) => opts.project.clone(),
            cli::DumpCommands::Strings(opts) => opts.project.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.project.clone(),
            cli::XRefCommands::From(args) => args.options.project.clone(),
            cli::XRefCommands::List(args) => args.options.project.clone(),
        },
        Commands::Stats(args) => args.options.project.clone(),
        Commands::Disasm(args) => args.options.project.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.project.clone(),
            cli::FindCommands::Bytes(args) => args.options.project.clone(),
            cli::FindCommands::Function(args) => args.options.project.clone(),
            cli::FindCommands::Calls(args) => args.options.project.clone(),
            cli::FindCommands::Crypto(opts) => opts.project.clone(),
            cli::FindCommands::Interesting(opts) => opts.project.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.project.clone(),
            cli::GraphCommands::Callers(args) => args.options.project.clone(),
            cli::GraphCommands::Callees(args) => args.options.project.clone(),
            cli::GraphCommands::Export(args) => args.options.project.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.project.clone(),
            cli::CommentCommands::Get(args) => args.options.project.clone(),
            cli::CommentCommands::Set(args) => args.project.clone(),
            cli::CommentCommands::Delete(args) => args.options.project.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => opts.project.clone(),
            cli::SymbolCommands::Get(args) => args.options.project.clone(),
            cli::SymbolCommands::Create(args) => args.project.clone(),
            cli::SymbolCommands::Delete(args) => args.options.project.clone(),
            cli::SymbolCommands::Rename(args) => args.project.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.project.clone(),
            cli::TypeCommands::Get(args) => args.options.project.clone(),
            cli::TypeCommands::Create(args) => args.project.clone(),
            cli::TypeCommands::Apply(args) => args.project.clone(),
            cli::TypeCommands::Delete(args) => args.project.clone(),
            cli::TypeCommands::Rename(args) => args.project.clone(),
            cli::TypeCommands::CreateEnum(args) => args.project.clone(),
            cli::TypeCommands::Typedef(args) => args.project.clone(),
            cli::TypeCommands::AddField(args) => args.project.clone(),
            cli::TypeCommands::DelField(args) => args.project.clone(),
        },
        Commands::Patch(cmd) => match cmd {
            cli::PatchCommands::Bytes(args) => args.project.clone(),
            cli::PatchCommands::Nop(args) => args.project.clone(),
            cli::PatchCommands::Export(args) => args.project.clone(),
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.project.clone(),
            cli::ScriptCommands::Python(args) => args.project.clone(),
            cli::ScriptCommands::Java(args) => args.project.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.project.clone(),
            cli::ProgramCommands::Open(args) => args.project.clone(),
            cli::ProgramCommands::Close(args) => args.project.clone(),
            cli::ProgramCommands::Delete(args) => args.project.clone(),
            cli::ProgramCommands::Info(args) => args.project.clone(),
            cli::ProgramCommands::Export(args) => args.project.clone(),
        },
        Commands::Diff(cmd) => match cmd {
            cli::DiffCommands::Programs(args) => args.project.clone(),
            cli::DiffCommands::Functions(args) => args.project.clone(),
        },
        Commands::Batch(args) => args.project.clone(),
        Commands::Rename(args) => args.project.clone(),
        _ => None,
    }
}

/// Extract the --program argument from a command's args, if present.
/// Enables program switching before query execution when the requested
/// program differs from the bridge's current program.
fn extract_program_from_command(command: &Commands) -> Option<String> {
    match command {
        Commands::Analyze(args) => args.program.clone(),
        Commands::Query(args) => args.program.clone(),
        Commands::Summary(args) => args.options.program.clone(),
        Commands::Decompile(args) => args.options.program.clone(),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(opts) => opts.program.clone(),
            cli::FunctionCommands::Decompile(args) => args.options.program.clone(),
            cli::FunctionCommands::Get(args) => args.options.program.clone(),
            cli::FunctionCommands::Disasm(args) => args.options.program.clone(),
            cli::FunctionCommands::Calls(args) => args.options.program.clone(),
            cli::FunctionCommands::XRefs(args) => args.options.program.clone(),
            cli::FunctionCommands::Rename(args) => args.program.clone(),
            cli::FunctionCommands::Create(args) => args.program.clone(),
            cli::FunctionCommands::Delete(args) => args.options.program.clone(),
            cli::FunctionCommands::SetSignature(args) => args.program.clone(),
            cli::FunctionCommands::SetReturnType(args) => args.program.clone(),
            cli::FunctionCommands::SetCallingConvention(args) => args.program.clone(),
            cli::FunctionCommands::SetVarType(args) => args.program.clone(),
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => opts.program.clone(),
            cli::StringsCommands::Refs(args) => args.options.program.clone(),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => opts.program.clone(),
            cli::MemoryCommands::Read(args) => args.options.program.clone(),
            cli::MemoryCommands::Write(args) => args.program.clone(),
            cli::MemoryCommands::Search(args) => args.options.program.clone(),
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => opts.program.clone(),
            cli::DumpCommands::Exports(opts) => opts.program.clone(),
            cli::DumpCommands::Functions(opts) => opts.program.clone(),
            cli::DumpCommands::Strings(opts) => opts.program.clone(),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => args.options.program.clone(),
            cli::XRefCommands::From(args) => args.options.program.clone(),
            cli::XRefCommands::List(args) => args.options.program.clone(),
        },
        Commands::Stats(args) => args.options.program.clone(),
        Commands::Disasm(args) => args.options.program.clone(),
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => args.options.program.clone(),
            cli::FindCommands::Bytes(args) => args.options.program.clone(),
            cli::FindCommands::Function(args) => args.options.program.clone(),
            cli::FindCommands::Calls(args) => args.options.program.clone(),
            cli::FindCommands::Crypto(opts) => opts.program.clone(),
            cli::FindCommands::Interesting(opts) => opts.program.clone(),
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => opts.program.clone(),
            cli::GraphCommands::Callers(args) => args.options.program.clone(),
            cli::GraphCommands::Callees(args) => args.options.program.clone(),
            cli::GraphCommands::Export(args) => args.options.program.clone(),
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => opts.program.clone(),
            cli::CommentCommands::Get(args) => args.options.program.clone(),
            cli::CommentCommands::Set(args) => args.program.clone(),
            cli::CommentCommands::Delete(args) => args.options.program.clone(),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => opts.program.clone(),
            cli::SymbolCommands::Get(args) => args.options.program.clone(),
            cli::SymbolCommands::Create(args) => args.program.clone(),
            cli::SymbolCommands::Delete(args) => args.options.program.clone(),
            cli::SymbolCommands::Rename(args) => args.program.clone(),
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => opts.program.clone(),
            cli::TypeCommands::Get(args) => args.options.program.clone(),
            cli::TypeCommands::Create(args) => args.program.clone(),
            cli::TypeCommands::Apply(args) => args.program.clone(),
            cli::TypeCommands::Delete(args) => args.program.clone(),
            cli::TypeCommands::Rename(args) => args.program.clone(),
            cli::TypeCommands::CreateEnum(args) => args.program.clone(),
            cli::TypeCommands::Typedef(args) => args.program.clone(),
            cli::TypeCommands::AddField(args) => args.program.clone(),
            cli::TypeCommands::DelField(args) => args.program.clone(),
        },
        Commands::Patch(cmd) => match cmd {
            cli::PatchCommands::Bytes(args) => args.program.clone(),
            cli::PatchCommands::Nop(args) => args.program.clone(),
            cli::PatchCommands::Export(args) => args.program.clone(),
        },
        Commands::Script(cmd) => match cmd {
            cli::ScriptCommands::Run(args) => args.program.clone(),
            cli::ScriptCommands::Python(args) => args.program.clone(),
            cli::ScriptCommands::Java(args) => args.program.clone(),
            cli::ScriptCommands::List => None,
        },
        Commands::Program(cmd) => match cmd {
            cli::ProgramCommands::List(args) => args.program.clone(),
            cli::ProgramCommands::Open(args) => args.program.clone(),
            cli::ProgramCommands::Close(args) => args.program.clone(),
            cli::ProgramCommands::Delete(args) => args.program.clone(),
            cli::ProgramCommands::Info(args) => args.program.clone(),
            cli::ProgramCommands::Export(args) => args.program.clone(),
        },
        Commands::Batch(args) => args.program.clone(),
        Commands::Rename(args) => args.program.clone(),
        _ => None,
    }
}

/// Extract QueryOptions from a command, if it has them.
fn extract_query_options(command: &Commands) -> Option<QueryOptions> {
    match command {
        Commands::Summary(args) => Some(args.options.clone()),
        Commands::Decompile(args) => Some(args.options.clone()),
        Commands::Disasm(args) => Some(args.options.clone()),
        Commands::Stats(args) => Some(args.options.clone()),
        Commands::Function(cmd) => match cmd {
            cli::FunctionCommands::List(opts) => Some(opts.clone()),
            cli::FunctionCommands::Get(args) => Some(args.options.clone()),
            cli::FunctionCommands::Decompile(args) => Some(args.options.clone()),
            cli::FunctionCommands::Disasm(args) => Some(args.options.clone()),
            cli::FunctionCommands::Calls(args) => Some(args.options.clone()),
            cli::FunctionCommands::XRefs(args) => Some(args.options.clone()),
            cli::FunctionCommands::Delete(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Strings(cmd) => match cmd {
            cli::StringsCommands::List(opts) => Some(opts.clone()),
            cli::StringsCommands::Refs(args) => Some(args.options.clone()),
        },
        Commands::Memory(cmd) => match cmd {
            cli::MemoryCommands::Map(opts) => Some(opts.clone()),
            cli::MemoryCommands::Read(args) => Some(args.options.clone()),
            cli::MemoryCommands::Search(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Dump(cmd) => match cmd {
            cli::DumpCommands::Imports(opts) => Some(opts.clone()),
            cli::DumpCommands::Exports(opts) => Some(opts.clone()),
            cli::DumpCommands::Functions(opts) => Some(opts.clone()),
            cli::DumpCommands::Strings(opts) => Some(opts.clone()),
        },
        Commands::XRef(cmd) => match cmd {
            cli::XRefCommands::To(args) => Some(args.options.clone()),
            cli::XRefCommands::From(args) => Some(args.options.clone()),
            cli::XRefCommands::List(args) => Some(args.options.clone()),
        },
        Commands::Symbol(cmd) => match cmd {
            cli::SymbolCommands::List(opts) => Some(opts.clone()),
            cli::SymbolCommands::Get(args) => Some(args.options.clone()),
            cli::SymbolCommands::Delete(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Type(cmd) => match cmd {
            cli::TypeCommands::List(opts) => Some(opts.clone()),
            cli::TypeCommands::Get(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Comment(cmd) => match cmd {
            cli::CommentCommands::List(opts) => Some(opts.clone()),
            cli::CommentCommands::Get(args) => Some(args.options.clone()),
            _ => None,
        },
        Commands::Graph(cmd) => match cmd {
            cli::GraphCommands::Calls(opts) => Some(opts.clone()),
            cli::GraphCommands::Callers(args) => Some(args.options.clone()),
            cli::GraphCommands::Callees(args) => Some(args.options.clone()),
            cli::GraphCommands::Export(args) => Some(args.options.clone()),
        },
        Commands::Find(cmd) => match cmd {
            cli::FindCommands::String(args) => Some(args.options.clone()),
            cli::FindCommands::Bytes(args) => Some(args.options.clone()),
            cli::FindCommands::Function(args) => Some(args.options.clone()),
            cli::FindCommands::Calls(args) => Some(args.options.clone()),
            cli::FindCommands::Crypto(opts) => Some(opts.clone()),
            cli::FindCommands::Interesting(opts) => Some(opts.clone()),
        },
        _ => None,
    }
}

/// Run a command that requires the bridge.
fn run_with_bridge(cli: Cli) -> anyhow::Result<()> {
    let config = Config::load()?;

    // Extract project from command args, fall back to global --project, then config default
    let project_from_cmd =
        extract_project_from_command(&cli.command).or_else(|| cli.project.clone());
    let project_path = resolve_project_path(&project_from_cmd, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ghidra installation directory not configured. Run 'ghidra setup' first."
            )
        })?;

    // Import and Quick produce their own result and don't need execute_via_bridge.
    // Other commands (including Analyze) produce a result via execute_via_bridge.
    use serde_json::json;
    let result = match &cli.command {
        Commands::Import(args) => {
            let binary_path = PathBuf::from(&args.binary);
            if !binary_path.exists() {
                anyhow::bail!("Binary not found: {}", args.binary);
            }

            // Acquire a bridge connection and the imported program's name. Three
            // hang-proof cases (see docs/plans/prescript-fix.md §3.3):
            //   1. Bridge already running    -> TCP import into the live project.
            //   2. Project exists, no bridge -> fast launch (Project mode), TCP import.
            //   3. Brand-new project         -> bootstrap via `-import -noanalysis`
            //      (only `-import` can create a project; analysis is skipped at
            //      launch and driven over TCP below).
            // The launch is bounded (the bridge binds its socket before analysis);
            // analysis afterwards runs as an unbounded TCP operation.
            let (client, program_name) = if let Some(port) =
                bridge::is_bridge_running(&project_path)
            {
                let client = BridgeClient::new(port);
                verify_bridge(&client)?;
                if !cli.quiet {
                    eprintln!("Importing into running bridge...");
                }
                let result = client.import_binary(&args.binary, args.program.as_deref())?;
                let name = args.program.clone().unwrap_or_else(|| {
                    result
                        .get("program")
                        .and_then(|p| p.as_str())
                        .unwrap_or("unknown")
                        .to_string()
                });
                client.open_program(&name)?;
                (client, name)
            } else if project_exists(&project_path) {
                if !cli.quiet {
                    eprintln!("Starting Ghidra bridge...");
                }
                let port = bridge::ensure_bridge_running(
                    &project_path,
                    &ghidra_install_dir,
                    BridgeStartMode::Project,
                )?;
                let client = BridgeClient::new(port);
                let result = client.import_binary(&args.binary, args.program.as_deref())?;
                let name = args.program.clone().unwrap_or_else(|| {
                    result
                        .get("program")
                        .and_then(|p| p.as_str())
                        .unwrap_or("unknown")
                        .to_string()
                });
                client.open_program(&name)?;
                (client, name)
            } else {
                if !cli.quiet {
                    eprintln!("Starting Ghidra bridge...");
                }
                let port = bridge::ensure_bridge_running(
                    &project_path,
                    &ghidra_install_dir,
                    BridgeStartMode::Import {
                        binary_path: args.binary.clone(),
                    },
                )?;
                // `-import` already loaded the binary; the bridge's currentProgram
                // is it. Prefer its real (domain) name for reporting.
                let client = BridgeClient::new(port);
                let name = client
                    .program_info()
                    .ok()
                    .and_then(|i| {
                        i.get("name")
                            .and_then(|n| n.as_str())
                            .map(|s| s.to_string())
                    })
                    .or_else(|| args.program.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                (client, name)
            };

            // Run analysis as an UNBOUNDED operation unless the user opted out.
            // handleAnalyze runs analyzeAll + program.save(), so the program
            // persists without relying on a clean bridge shutdown.
            let analyze_data = if args.no_analyze {
                if !cli.quiet {
                    eprintln!("Skipping analysis (--no-analyze).");
                }
                json!(null)
            } else {
                if !cli.quiet {
                    eprintln!("Analyzing {}...", program_name);
                }
                let d = client.analyze()?;
                if !cli.quiet {
                    eprintln!("Analysis complete!");
                }
                d
            };

            if !cli.quiet {
                eprintln!("Successfully imported as: {}", program_name);
            }
            json!({
                "command": "import",
                "program": program_name,
                "status": "success",
                "data": { "analyze": analyze_data }
            })
        }

        _ => {
            // For all bridge commands (including Analyze), ensure bridge is running
            let client = if let Some(port) = bridge::is_bridge_running(&project_path) {
                let client = BridgeClient::new(port);
                verify_bridge(&client)?;
                client
            } else {
                // Auto-start bridge - use specific program if available, otherwise project mode
                let mode = if let Some(program) = extract_program_from_command(&cli.command)
                    .or_else(|| cli.program.clone())
                    .or_else(|| config.get_default_program())
                {
                    BridgeStartMode::Process {
                        program_name: program,
                    }
                } else {
                    BridgeStartMode::Project
                };

                if !cli.quiet {
                    eprintln!("Starting Ghidra bridge...");
                }
                let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                if !cli.quiet {
                    eprintln!("Bridge ready.");
                }
                BridgeClient::new(port)
            };

            // Switch to requested program if it differs from the bridge's current program
            if let Some(requested_program) =
                extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
            {
                if let Ok(info) = client.program_info() {
                    let current = info.get("name").and_then(|n| n.as_str()).unwrap_or("");
                    if current != requested_program {
                        client.open_program(&requested_program)?;
                    }
                } else {
                    client.open_program(&requested_program)?;
                }
            }

            match execute_via_bridge(&client, &cli.command, cli.quiet, config.default_limit) {
                Ok(value) => value,
                Err(err) if is_unknown_command_error(&err) => {
                    if !cli.quiet {
                        eprintln!(
                            "Bridge command not supported by running instance. Restarting bridge and retrying..."
                        );
                    }

                    // Running bridge may be from an older script; force restart to load
                    // the embedded bridge matching this CLI version.
                    let _ = bridge::stop_bridge(&project_path);
                    let mode = if let Some(program) = extract_program_from_command(&cli.command)
                        .or_else(|| cli.program.clone())
                        .or_else(|| config.get_default_program())
                    {
                        BridgeStartMode::Process {
                            program_name: program,
                        }
                    } else {
                        BridgeStartMode::Project
                    };
                    let port =
                        bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;
                    let retry_client = BridgeClient::new(port);

                    if let Some(requested_program) =
                        extract_program_from_command(&cli.command).or_else(|| cli.program.clone())
                    {
                        if let Ok(info) = retry_client.program_info() {
                            let current = info.get("name").and_then(|n| n.as_str()).unwrap_or("");
                            if current != requested_program {
                                retry_client.open_program(&requested_program)?;
                            }
                        } else {
                            retry_client.open_program(&requested_program)?;
                        }
                    }

                    execute_via_bridge(
                        &retry_client,
                        &cli.command,
                        cli.quiet,
                        config.default_limit,
                    )?
                }
                Err(err) => return Err(err),
            }
        }
    };

    // Check for .NET decompilation and warn
    if !cli.quiet {
        check_dotnet_decompile_warning(&cli.command, &result);
    }

    // Determine output format: explicit -o flag > --json/--pretty > TTY detection
    let opts = extract_query_options(&cli.command);
    let explicit_format = opts
        .as_ref()
        .and_then(|o| o.format.as_ref())
        .map(|f| OutputFormat::from_str(f))
        .transpose()
        .ok()
        .flatten();

    let format = if let Some(fmt) = explicit_format {
        fmt
    } else if cli.pretty {
        OutputFormat::Json
    } else if cli.json || opts.as_ref().is_some_and(|o| o.json) {
        OutputFormat::JsonCompact
    } else {
        auto_detect_format(std::io::stdout().is_terminal())
    };

    // Unwrap bridge response envelopes before formatting
    let values = unwrap_bridge_response(result);

    // Apply Rust-side query processing (filter, fields, sort) if QueryOptions are present
    if let Some(opts) = &opts {
        if let Ok(Some(query)) = Query::from_options(opts, format) {
            let output = query.process_results(values)?;
            if !output.is_empty() {
                println!("{}", output);
            }
            return Ok(());
        }
    }

    let formatter = DefaultFormatter;
    let output = formatter.format(&values, format)?;
    if !output.is_empty() {
        println!("{}", output);
    }
    Ok(())
}

fn is_unknown_command_error(err: &anyhow::Error) -> bool {
    err.to_string().contains("Unknown command:")
}

/// Execute a command via the bridge client.
fn execute_via_bridge(
    client: &BridgeClient,
    command: &Commands,
    quiet: bool,
    default_limit: Option<usize>,
) -> anyhow::Result<serde_json::Value> {
    use serde_json::json;

    match command {
        // Analyze shares the generic dispatch path with all query commands
        Commands::Analyze(_) => {
            if !quiet {
                eprintln!("Analyzing...");
            }
            let result = client.analyze()?;
            if !quiet {
                eprintln!("Analysis complete!");
            }
            Ok(json!({
                "command": "analyze",
                "status": "success",
                "data": result
            }))
        }
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => client.list_functions(args.limit.or(default_limit), args.filter.clone()),
            "strings" => client.list_strings(args.limit.or(default_limit), args.filter.clone()),
            "imports" => client.list_imports(),
            "exports" => client.list_exports(),
            "memory" => client.memory_map(),
            other => anyhow::bail!("Query type '{}' not supported", other),
        },
        Commands::Decompile(args) => client.decompile(
            args.resolved_target().to_string(),
            args.with_vars,
            args.with_params,
        ),
        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(opts) => {
                    client.list_functions(opts.limit.or(default_limit), opts.filter.clone())
                }
                FunctionCommands::Decompile(args) => client.decompile(
                    args.resolved_target().to_string(),
                    args.with_vars,
                    args.with_params,
                ),
                FunctionCommands::Get(args) => client.send_command(
                    "get_function",
                    Some(json!({"address": args.resolved_target()})),
                ),
                FunctionCommands::Disasm(args) => client.disasm(args.resolved_target(), None),
                FunctionCommands::Calls(args) => client.find_calls(args.resolved_target()),
                FunctionCommands::XRefs(args) => {
                    client.xrefs_to(args.resolved_target().to_string())
                }
                FunctionCommands::Rename(args) => client.send_command(
                    "rename_function",
                    Some(json!({
                        "old_name": args.old_name,
                        "new_name": args.new_name,
                    })),
                ),
                FunctionCommands::Create(args) => client.send_command(
                    "create_function",
                    Some(json!({
                        "address": args.address,
                        "name": args.name,
                    })),
                ),
                FunctionCommands::Delete(args) => client.send_command(
                    "delete_function",
                    Some(json!({
                        "address": args.resolved_target(),
                    })),
                ),
                FunctionCommands::SetSignature(args) => client.send_command(
                    "function_set_signature",
                    Some(json!({
                        "target": args.resolved_target(),
                        "signature": args.signature,
                    })),
                ),
                FunctionCommands::SetReturnType(args) => client.send_command(
                    "function_set_return_type",
                    Some(json!({
                        "target": args.resolved_target(),
                        "return_type": args.return_type,
                    })),
                ),
                FunctionCommands::SetCallingConvention(args) => client.send_command(
                    "function_set_calling_convention",
                    Some(json!({
                        "target": args.resolved_target(),
                        "convention": args.convention,
                    })),
                ),
                FunctionCommands::SetVarType(args) => client.send_command(
                    "set_var_type",
                    Some(json!({
                        "function": args.resolved_target(),
                        "var_name": args.var_name,
                        "type_name": args.type_name,
                    })),
                ),
            }
        }
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(opts) => {
                    client.list_strings(opts.limit.or(default_limit), opts.filter.clone())
                }
                StringsCommands::Refs(args) => client.xrefs_to(args.string.clone()),
            }
        }
        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map(),
                MemoryCommands::Read(args) => client.send_command(
                    "read_memory",
                    Some(json!({
                        "address": args.address,
                        "size": args.size,
                    })),
                ),
                MemoryCommands::Write(args) => client.send_command(
                    "write_memory",
                    Some(json!({
                        "address": args.address,
                        "bytes": args.bytes,
                    })),
                ),
                MemoryCommands::Search(args) => client.send_command(
                    "search_memory",
                    Some(json!({
                        "pattern": args.pattern,
                    })),
                ),
            }
        }
        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(_) => client.list_imports(),
                DumpCommands::Exports(_) => client.list_exports(),
                DumpCommands::Functions(opts) => {
                    client.list_functions(opts.limit.or(default_limit), opts.filter.clone())
                }
                DumpCommands::Strings(opts) => {
                    client.list_strings(opts.limit.or(default_limit), opts.filter.clone())
                }
            }
        }
        Commands::Summary(_) => client.program_info(),
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => client.xrefs_to(args.resolved_target().to_string()),
                XRefCommands::From(args) => client.xrefs_from(args.resolved_target().to_string()),
                XRefCommands::List(args) => {
                    client.send_command("xrefs_list", Some(json!({"address": args.resolved_target()})))
                }
            }
        }
        Commands::Program(cmd) => {
            use cli::ProgramCommands;
            match cmd {
                ProgramCommands::List(_) => client.list_programs(),
                ProgramCommands::Open(args) => {
                    let program = args.program.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Program name required. Use --program <name>")
                    })?;
                    client.open_program(program)
                }
                ProgramCommands::Close(_) => client.program_close(),
                ProgramCommands::Delete(args) => {
                    let program = args
                        .program
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Program name required"))?;
                    client.program_delete(program)
                }
                ProgramCommands::Info(_) => client.program_info(),
                ProgramCommands::Export(args) => {
                    client.program_export(&args.format, args.output.as_deref())
                }
            }
        }
        Commands::Symbol(cmd) => {
            use cli::SymbolCommands;
            match cmd {
                SymbolCommands::List(opts) => {
                    client.symbol_list(opts.limit.or(default_limit), opts.filter.as_deref())
                }
                SymbolCommands::Get(args) => client.symbol_get(&args.name),
                SymbolCommands::Create(args) => client.symbol_create(&args.address, &args.name),
                SymbolCommands::Delete(args) => client.symbol_delete(&args.name),
                SymbolCommands::Rename(args) => {
                    client.symbol_rename(&args.old_name, &args.new_name)
                }
            }
        }
        Commands::Type(cmd) => {
            use cli::TypeCommands;
            match cmd {
                TypeCommands::List(opts) => {
                    client.type_list(opts.limit.or(default_limit), opts.filter.as_deref())
                }
                TypeCommands::Get(args) => client.type_get(&args.name),
                TypeCommands::Create(args) => client.type_create(&args.definition),
                TypeCommands::Apply(args) => client.type_apply(&args.address, &args.type_name),
                TypeCommands::Delete(args) => client.send_command(
                    "type_delete",
                    Some(json!({"name": args.name})),
                ),
                TypeCommands::Rename(args) => client.send_command(
                    "type_rename",
                    Some(json!({"old_name": args.old_name, "new_name": args.new_name})),
                ),
                TypeCommands::CreateEnum(args) => client.send_command(
                    "type_create_enum",
                    Some(json!({
                        "name": args.name,
                        "values": args.values,
                        "size": args.size,
                    })),
                ),
                TypeCommands::Typedef(args) => client.send_command(
                    "type_typedef",
                    Some(json!({
                        "name": args.name,
                        "base_type": args.base_type,
                    })),
                ),
                TypeCommands::AddField(args) => client.send_command(
                    "type_add_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                        "field_type": args.field_type,
                        "offset": args.offset,
                        "size": args.size,
                    })),
                ),
                TypeCommands::DelField(args) => client.send_command(
                    "type_del_field",
                    Some(json!({
                        "type_name": args.type_name,
                        "field_name": args.name,
                    })),
                ),
            }
        }
        Commands::Comment(cmd) => {
            use cli::CommentCommands;
            match cmd {
                CommentCommands::List(opts) => {
                    client.comment_list(opts.limit.or(default_limit), opts.filter.as_deref())
                }
                CommentCommands::Get(args) => client.comment_get(&args.address),
                CommentCommands::Set(args) => {
                    client.comment_set(&args.address, &args.text, args.comment_type.as_deref())
                }
                CommentCommands::Delete(args) => client.comment_delete(&args.address),
            }
        }
        Commands::Graph(cmd) => {
            use cli::GraphCommands;
            match cmd {
                GraphCommands::Calls(opts) => client.graph_calls(opts.limit.or(default_limit)),
                GraphCommands::Callers(args) => {
                    client.graph_callers(args.resolved_target(), args.depth)
                }
                GraphCommands::Callees(args) => {
                    client.graph_callees(args.resolved_target(), args.depth)
                }
                GraphCommands::Export(args) => client.graph_export(&args.format),
            }
        }
        Commands::Find(cmd) => {
            use cli::FindCommands;
            match cmd {
                FindCommands::String(args) => client.find_string(&args.pattern),
                FindCommands::Bytes(args) => client.find_bytes(&args.hex),
                FindCommands::Function(args) => client.find_function(&args.pattern),
                FindCommands::Calls(args) => client.find_calls(args.resolved_target()),
                FindCommands::Crypto(_) => client.find_crypto(),
                FindCommands::Interesting(_) => client.find_interesting(),
            }
        }
        Commands::Diff(cmd) => {
            use cli::DiffCommands;
            match cmd {
                DiffCommands::Programs(args) => {
                    client.diff_programs(&args.program1, &args.program2)
                }
                DiffCommands::Functions(args) => client.diff_functions(&args.func1, &args.func2),
            }
        }
        Commands::Patch(cmd) => {
            use cli::PatchCommands;
            match cmd {
                PatchCommands::Bytes(args) => client.patch_bytes(&args.address, &args.hex),
                PatchCommands::Nop(args) => client.patch_nop(&args.address),
                PatchCommands::Export(args) => client.patch_export(&args.output),
            }
        }
        Commands::Script(cmd) => {
            use cli::ScriptCommands;
            match cmd {
                ScriptCommands::Run(args) => client.script_run(&args.script_path, &args.args),
                ScriptCommands::Python(args) => client.script_python(&args.code),
                ScriptCommands::Java(args) => client.script_java(&args.code),
                ScriptCommands::List => client.script_list(),
            }
        }
        Commands::Disasm(args) => client.disasm(args.resolved_target(), args.num_instructions),
        Commands::Batch(args) => {
            // Read batch file and execute each command locally
            let content = std::fs::read_to_string(&args.script_file)
                .map_err(|e| anyhow::anyhow!("Failed to read batch file: {}", e))?;
            let lines: Vec<&str> = content
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .collect();

            let mut results = Vec::new();
            for line in &lines {
                let words: Vec<&str> = std::iter::once("ghidra")
                    .chain(line.split_whitespace())
                    .collect();
                let sub_result = match Cli::try_parse_from(&words) {
                    Ok(sub_cli) => {
                        execute_via_bridge(client, &sub_cli.command, true, default_limit)
                    }
                    Err(e) => Err(anyhow::anyhow!("{}", e)),
                };
                match sub_result {
                    Ok(val) => results.push(json!({"command": line.trim(), "result": val})),
                    Err(e) => results.push(json!({"command": line.trim(), "error": e.to_string()})),
                }
            }

            Ok(json!({
                "commands_parsed": lines.len(),
                "results": results
            }))
        }
        Commands::Stats(_) => client.stats(),
        Commands::Rename(args) => client.symbol_rename(&args.old_name, &args.new_name),
        _ => anyhow::bail!("Command not supported"),
    }
}

/// Dispatch bridge management commands (top-level start/stop/restart/status/ping).
fn handle_bridge_command(cli: Cli) -> anyhow::Result<()> {
    // Global --project/--program flags serve as fallbacks for subcommand-level args
    let global_project = cli.project.clone();
    let global_program = cli.program.clone();
    match cli.command {
        Commands::Start { project, program } => {
            handle_bridge_start(project.or(global_project), program.or(global_program))
        }
        Commands::Stop { project } => handle_bridge_stop(project.or(global_project)),
        Commands::Restart { project, program } => {
            let proj = project.or(global_project);
            let prog = program.or(global_program);
            handle_bridge_stop(proj.clone())?;
            std::thread::sleep(std::time::Duration::from_secs(1));
            handle_bridge_start(proj, prog)
        }
        Commands::Status { project } => handle_bridge_status(project.or(global_project)),
        Commands::Ping { project } => handle_bridge_ping(project.or(global_project)),
        _ => unreachable!(),
    }
}

/// Start the bridge for a project.
fn handle_bridge_start(project: Option<String>, program: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    let ghidra_install_dir = config
        .ghidra_install_dir
        .clone()
        .or_else(|| config.get_ghidra_install_dir().ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Ghidra installation directory not configured. Run 'ghidra setup' first."
            )
        })?;

    // Check if bridge is already running
    if bridge::is_bridge_running(&project_path).is_some() {
        println!(
            "Bridge is already running for project: {}",
            project_path.display()
        );
        return Ok(());
    }

    // Determine start mode
    let mode = if let Some(prog) = program {
        BridgeStartMode::Process { program_name: prog }
    } else if let Some(prog) = config.get_default_program() {
        BridgeStartMode::Process { program_name: prog }
    } else {
        BridgeStartMode::Project
    };

    println!("Starting bridge for project: {}", project_path.display());

    let port = bridge::ensure_bridge_running(&project_path, &ghidra_install_dir, mode)?;

    println!("Bridge started on port {}", port);
    Ok(())
}

/// Stop the bridge for a project.
fn handle_bridge_stop(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    if bridge::is_bridge_running(&project_path).is_some() {
        println!("Stopping bridge...");
        bridge::stop_bridge(&project_path)?;
        println!("Bridge stopped");
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

/// Get bridge status for a project.
fn handle_bridge_status(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    match bridge::bridge_status(&project_path)? {
        BridgeStatus::Running { port, pid } => {
            println!("Bridge is running:");
            println!("  PID: {}", pid);
            println!("  Port: {}", port);
            println!("  Project: {}", project_path.display());

            // Try to get extended info from the bridge
            let client = BridgeClient::new(port);
            if let Ok(info) = client.bridge_info() {
                if let Some(prog) = info.get("current_program").and_then(|v| v.as_str()) {
                    println!("  Current program: {}", prog);
                }
                if let Some(count) = info.get("program_count").and_then(|v| v.as_u64()) {
                    println!("  Programs: {}", count);
                }
            }
        }
        BridgeStatus::Stopped => {
            println!("No bridge running for project: {}", project_path.display());
        }
    }

    Ok(())
}

/// Ping the bridge.
fn handle_bridge_ping(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(port) = bridge::is_bridge_running(&project_path) {
        let client = BridgeClient::new(port);
        if client.ping()? {
            println!("Bridge is responsive");
        } else {
            println!("Bridge is not responding");
        }
    } else {
        println!("No bridge running for project: {}", project_path.display());
    }

    Ok(())
}

/// Handle the setup command - download and install Ghidra.
async fn run_setup(cli: Cli) -> anyhow::Result<()> {
    let args = match cli.command {
        Commands::Setup(args) => args,
        _ => unreachable!(),
    };

    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java — Ghidra needs a full JDK (not a JRE) to compile scripts.
    if !args.force {
        let explicit = Config::load().ok().and_then(|c| c.get_java_home());
        match ghidra::java::resolve_jdk(explicit.as_deref(), ghidra::java::DEFAULT_MIN_JAVA) {
            ghidra::java::JavaStatus::Ok(info) => {
                println!(
                    "✓ JDK {} found at {} (via {})",
                    info.major,
                    info.home.display(),
                    info.source
                );
            }
            other => {
                eprintln!(
                    "Java prerequisite check failed: {}",
                    ghidra::java::describe_failure(&other)
                );
                eprintln!("Use --force to continue anyway.");
                std::process::exit(1);
            }
        }
    } else {
        println!("Skipping Java check (--force specified)");
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install Ghidra
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\nSuccess! Ghidra installed at: {}", final_path.display());
    println!("Configuration updated.");

    // 5. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("Verification passed!");
        println!("\nYou can now run: ghidra import <binary> --project <name>");
    } else {
        println!("Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or run 'ghidra setup'.");
    }

    // Set default project directory
    let home = dirs::home_dir().ok_or_else(|| {
        GhidraError::ConfigError("Could not determine home directory".to_string())
    })?;
    let project_dir = home.join(".ghidra-projects");
    config.ghidra_project_dir = Some(project_dir.clone());

    println!("\nProject directory: {}", project_dir.display());

    // Save config
    config.save()?;

    println!(
        "\nConfiguration saved to: {}",
        Config::config_path()?.display()
    );
    println!("\nRun 'ghidra doctor' to verify your installation.");

    Ok(())
}

fn handle_doctor() -> anyhow::Result<()> {
    println!("Ghidra CLI Doctor");
    println!("=================\n");

    let config = Config::load()?;

    // Check Ghidra installation
    print!("Checking Ghidra installation... ");
    match config.get_ghidra_install_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: OK");
                    } else {
                        println!("  analyzeHeadless: NOT FOUND");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check Java
    // Check Java — must be a full JDK (Ghidra compiles scripts at runtime).
    use ghidra::java::JavaStatus;
    let install_dir = config.get_ghidra_install_dir().ok();
    let min = install_dir
        .as_deref()
        .map(ghidra::java::ghidra_min_java)
        .unwrap_or(ghidra::java::DEFAULT_MIN_JAVA);
    let explicit = config.get_java_home();

    print!("\nChecking Java (full JDK {}+)... ", min);
    match ghidra::java::resolve_jdk(explicit.as_deref(), min) {
        JavaStatus::Ok(info) => {
            println!("OK");
            println!(
                "  JDK {} at {} (selected via {})",
                info.major,
                info.home.display(),
                info.source
            );

            // Real health check: compile the embedded bridge script against the
            // installed Ghidra. Catches API incompatibilities and JRE issues.
            if let Some(install) = &install_dir {
                print!("\nChecking bridge script compiles... ");
                match ghidra::bridge::compile_check(install, &info.home) {
                    Ok(()) => println!("OK"),
                    Err(errs) => {
                        println!("FAILED");
                        for line in errs.lines() {
                            println!("  {}", line);
                        }
                    }
                }
            }
        }
        JavaStatus::JreNoCompiler { home, major } => {
            println!("FAILED");
            println!(
                "  JRE detected: Java {} at {} has no javac / jdk.compiler module.",
                major,
                home.display()
            );
            println!(
                "  Ghidra requires a full JDK {}+ to compile scripts (a JRE cannot work).",
                min
            );
            println!("  Install a JDK, or select one with --java-home / GHIDRA_CLI_JAVA_HOME / config `java_home`.");
        }
        JavaStatus::WrongVersion { home, major, min } => {
            println!("FAILED");
            println!(
                "  JDK {} at {} is below the required JDK {}+.",
                major,
                home.display(),
                min
            );
        }
        JavaStatus::NotFound => {
            println!("FAILED");
            println!("  No Java found. Install a full JDK {}+ or set --java-home.", min);
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("OK");
            println!("  Location: {}", dir.display());
            println!(
                "  Exists: {}",
                if dir.exists() {
                    "yes"
                } else {
                    "no (will be created)"
                }
            );
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("OK");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {}", e);
        }
    }

    println!("\nDone!");
    Ok(())
}

fn handle_version() -> anyhow::Result<()> {
    println!("ghidra-cli {}", env!("CARGO_PKG_VERSION"));
    println!("Rust CLI for Ghidra reverse engineering");
    Ok(())
}

fn handle_config_command(cmd: cli::ConfigCommands) -> anyhow::Result<()> {
    use cli::ConfigCommands;

    match cmd {
        ConfigCommands::List => {
            let config = Config::load()?;
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigCommands::Get { key } => {
            let config = Config::load()?;
            let yaml = serde_yaml::to_value(&config)?;
            if let Some(value) = yaml.get(&key) {
                println!("{}", serde_yaml::to_string(value)?);
            } else {
                println!("Key not found: {}", key);
            }
        }
        ConfigCommands::Set { key, value } => {
            let mut config = Config::load()?;
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => {
                    let timeout: u64 = value.parse().map_err(|_| {
                        GhidraError::ConfigError("Invalid timeout value".to_string())
                    })?;
                    config.timeout = Some(timeout);
                }
                "ghidra_install_dir" => config.ghidra_install_dir = Some(PathBuf::from(value)),
                "ghidra_project_dir" => config.ghidra_project_dir = Some(PathBuf::from(value)),
                "default_program" => config.default_program = Some(value),
                "default_project" => config.default_project = Some(value),
                "default_limit" => {
                    let limit: usize = value
                        .parse()
                        .map_err(|_| GhidraError::ConfigError("Invalid limit value".to_string()))?;
                    config.default_limit = Some(limit);
                }
                _ => {
                    anyhow::bail!("Unknown config key: {}", key);
                }
            }
            config.save()?;
            println!("Configuration updated");
        }
        ConfigCommands::Reset => {
            let config = Config::default();
            config.save()?;
            println!("Configuration reset to defaults");
        }
    }

    Ok(())
}

fn handle_set_default(args: cli::SetDefaultArgs) -> anyhow::Result<()> {
    let mut config = Config::load()?;

    match args.kind.as_str() {
        "program" => {
            config.default_program = Some(args.value.clone());
            config.save()?;
            println!("Default program set to: {}", args.value);
        }
        "project" => {
            config.default_project = Some(args.value.clone());
            config.save()?;
            println!("Default project set to: {}", args.value);
        }
        _ => {
            anyhow::bail!(format!("Unknown default kind: {}", args.kind));
        }
    }

    Ok(())
}

fn handle_project_command(cmd: cli::ProjectCommands) -> anyhow::Result<()> {
    use cli::ProjectCommands;

    let config = Config::load()?;
    let client = GhidraClient::new(config)?;

    match cmd {
        ProjectCommands::Create { name } => {
            client.create_project(&name)?;
            println!("Project '{}' created", name);
        }
        ProjectCommands::List => {
            let project_dir = client.get_project_dir();
            if !project_dir.exists() {
                println!("No projects found");
                return Ok(());
            }

            println!("Projects:");
            for entry in std::fs::read_dir(project_dir)? {
                let entry = entry?;
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        println!("  {}", name);
                    }
                }
            }
        }
        ProjectCommands::Delete { name } => {
            // analyzeHeadless materializes a project as sibling files
            // `<parent>/<basename>.gpr` (descriptor) + `<basename>.rep` (data dir),
            // NOT a `<parent>/<basename>` directory. Derive the real paths from the
            // basename so absolute project names work too. `create_project` may
            // also have left an empty `<parent>/<basename>` directory.
            let project_path = client.get_project_path(&name);
            let (basename, parent) =
                match (project_path.file_name(), project_path.parent()) {
                    (Some(f), Some(p)) => (f.to_string_lossy().to_string(), p.to_path_buf()),
                    _ => {
                        println!("Project '{}' not found", name);
                        return Ok(());
                    }
                };
            let gpr = parent.join(format!("{}.gpr", basename));
            let rep = parent.join(format!("{}.rep", basename));
            let legacy_dir = project_path.clone();

            if !gpr.exists() && !rep.exists() && !legacy_dir.is_dir() {
                println!("Project '{}' not found", name);
                return Ok(());
            }

            // Stop any running bridge first so the JVM releases the project lock
            // before we delete its files. stop_bridge also clears the stale
            // port/pid/`.lock`/`.lock~` files via cleanup_stale_files.
            let _ = bridge::stop_bridge(&project_path);

            if gpr.exists() {
                std::fs::remove_file(&gpr)?;
            }
            if rep.exists() {
                std::fs::remove_dir_all(&rep)?;
            }
            if legacy_dir.is_dir() {
                std::fs::remove_dir_all(&legacy_dir)?;
            }
            println!("Project '{}' deleted", name);
        }
        ProjectCommands::Info { name } => {
            let project_name = name.unwrap_or_else(|| "default".to_string());
            let project_path = client.get_project_path(&project_name);
            println!("Project: {}", project_name);
            println!("Path: {}", project_path.display());
            println!("Exists: {}", project_path.exists());
        }
    }

    Ok(())
}

/// Check if a decompile result looks like .NET managed code and warn the user.
fn check_dotnet_decompile_warning(command: &Commands, result: &serde_json::Value) {
    let is_decompile = matches!(
        command,
        Commands::Decompile(_) | Commands::Function(cli::FunctionCommands::Decompile(_))
    );
    if !is_decompile {
        return;
    }

    if let Some(code) = result.get("code").and_then(|c| c.as_str()) {
        if code.contains("halt_baddata()") || code.contains(".NET CLR Managed Code") {
            eprintln!(
                "Warning: This appears to be .NET managed code. Ghidra cannot decompile .NET IL bytecode.\n\
                 Consider using a .NET decompiler (e.g., ilspy-cli) for better results."
            );
        }
    }
}

/// Unwrap bridge response envelopes into a flat array of objects.
///
/// Bridge returns envelopes like `{"count": N, "functions": [...]}`.
/// This extracts the inner array so formatters can render individual items.
fn unwrap_bridge_response(value: serde_json::Value) -> Vec<serde_json::Value> {
    // Already an array - return as-is
    if let serde_json::Value::Array(arr) = &value {
        return arr.clone();
    }

    // Must be an object to unwrap
    let obj = match value {
        serde_json::Value::Object(ref map) => map,
        other => return vec![other],
    };

    // Known array keys from bridge responses
    const ARRAY_KEYS: &[&str] = &[
        "functions",
        "strings",
        "imports",
        "exports",
        "blocks",
        "xrefs",
        "results",
        "programs",
        "types",
        "comments",
        "symbols",
        "callers",
        "callees",
        "calls",
        "instructions",
        "sections",
        "references",
    ];

    // Metadata keys that accompany array keys (not data themselves)
    const META_KEYS: &[&str] = &[
        "count",
        "target",
        "function",
        "command",
        "status",
        "current_program_name",
        "has_current_program",
        "data",
    ];

    // Special case: decompile responses have a "code" key - return as-is for special rendering
    if obj.contains_key("code") {
        return vec![value];
    }

    // Look for a known array key
    for &key in ARRAY_KEYS {
        if let Some(serde_json::Value::Array(arr)) = obj.get(key) {
            // Verify remaining keys are metadata
            let all_meta = obj
                .keys()
                .all(|k| k == key || META_KEYS.contains(&k.as_str()));
            if all_meta {
                return arr.clone();
            }
        }
    }

    // No known array key found - return as single-item vec
    vec![value]
}

/// Verify that a bridge is actually responding to commands.
fn verify_bridge(client: &BridgeClient) -> anyhow::Result<()> {
    if !client.ping()? {
        anyhow::bail!("Bridge not responding to ping");
    }
    Ok(())
}

/// Whether a Ghidra project already exists on disk for the given project path.
///
/// `project_path` is `<parent>/<name>`; analyzeHeadless materializes the project
/// as sibling `<parent>/<name>.gpr` (project file) and `<parent>/<name>.rep`
/// (project directory). Either marks an existing project we can `-process`.
fn project_exists(project_path: &Path) -> bool {
    match (project_path.file_name(), project_path.parent()) {
        (Some(name), Some(parent)) => {
            let name = name.to_string_lossy();
            parent.join(format!("{}.gpr", name)).exists()
                || parent.join(format!("{}.rep", name)).exists()
        }
        _ => false,
    }
}

/// Resolve a project name to its full path on disk.
fn resolve_project_path(project: &Option<String>, config: &Config) -> anyhow::Result<PathBuf> {
    let project_name = project
        .clone()
        .or_else(|| config.default_project.clone())
        .ok_or_else(|| anyhow::anyhow!("No project specified and no default project configured"))?;

    let project_dir = config.get_project_dir()?;

    if PathBuf::from(&project_name).is_absolute() {
        Ok(PathBuf::from(project_name))
    } else {
        Ok(project_dir.join(project_name))
    }
}
