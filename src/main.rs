mod cli;
mod config;
mod daemon;
mod error;
mod filter;
mod format;
mod ghidra;
mod ipc;
mod query;

use clap::Parser;
use cli::{Cli, Commands, DaemonCommands, SetupArgs};
use config::Config;
use daemon::process::{ensure_not_running, get_data_dir, get_running_daemon_info};
use daemon::{run as run_daemon, DaemonConfig};
use error::{GhidraError, Result};
use format::{auto_detect_format, DefaultFormatter, Formatter, OutputFormat};
use ghidra::GhidraClient;
use std::path::{Path, PathBuf};
use tracing::info;

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match &cli.command {
        Commands::Daemon(_) | Commands::Setup(_) => {
            // Daemon and Setup commands are async
            run_async(cli).await
        }
        _ => {
            // Other commands can be sync or we check if daemon is running
            run_with_daemon_check(cli).await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        // Non-daemon commands
        Commands::Init => handle_init(),
        Commands::Doctor => handle_doctor(),
        Commands::Version => handle_version(),
        Commands::Config(cmd) => handle_config_command(cmd),
        Commands::SetDefault(args) => handle_set_default(args),
        Commands::Project(args) => handle_project_command(args.command),
        // Commands requiring daemon are handled by run_with_daemon_check
        Commands::Import(_)
        | Commands::Analyze(_)
        | Commands::Quick(_)
        | Commands::Query(_)
        | Commands::Summary(_)
        | Commands::Function(_)
        | Commands::Strings(_)
        | Commands::Memory(_)
        | Commands::Dump(_)
        | Commands::Decompile(_)
        | Commands::XRef(_) => {
            unreachable!("Daemon-required commands should go through run_with_daemon_check")
        }
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}

/// Run async commands (daemon management, setup).
async fn run_async(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Daemon(cmd) => handle_daemon_command(cmd).await,
        Commands::Setup(args) => handle_setup(args).await,
        _ => unreachable!("run_async called with non-async command"),
    }
}

/// Determines if a command requires the daemon to be running.
fn requires_daemon(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Import(_)
            | Commands::Analyze(_)
            | Commands::Quick(_)
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
            | Commands::Queue(_)
    )
}

/// Run commands with daemon check - route through daemon if required.
async fn run_with_daemon_check(cli: Cli) -> anyhow::Result<()> {
    // Commands that don't require daemon can run directly
    if !requires_daemon(&cli.command) {
        return run(cli);
    }

    let config = Config::load()?;
    let project_path = config.get_project_dir()?;

    ensure_daemon_running(&project_path).await?;

    match ipc::client::DaemonClient::connect(&project_path).await {
        Ok(mut client) => {
            info!("Connected to daemon via IPC");
            let output =
                execute_via_daemon(&mut client, &cli.command, cli.json, cli.pretty).await?;
            if !output.is_empty() {
                println!("{}", output);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("Error: Failed to connect to daemon: {}", e);
            eprintln!();
            eprintln!("The daemon may still be starting. Try again in a moment.");
            std::process::exit(1);
        }
    }
}

/// Ensure daemon is running for the given project path.
async fn ensure_daemon_running(project_path: &Path) -> anyhow::Result<()> {
    let data_dir = get_data_dir()?;

    if get_running_daemon_info(&data_dir, project_path)?.is_some() {
        return Ok(());
    }

    let config = Config::load()?;
    let log_file = data_dir.join("daemon.log");

    let daemon_config = DaemonConfig {
        project_path: project_path.to_path_buf(),
        ghidra_install_dir: config.ghidra_install_dir,
        log_file,
        program_name: config.default_program.clone(),
    };

    #[cfg(unix)]
    {
        daemonize_unix(daemon_config, None)?;
    }

    #[cfg(windows)]
    {
        daemonize_windows(daemon_config, None)?;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    Ok(())
}

/// Execute a command via the daemon IPC connection.
async fn execute_via_daemon(
    client: &mut ipc::client::DaemonClient,
    command: &Commands,
    json_flag: bool,
    pretty_flag: bool,
) -> anyhow::Result<String> {
    let result = match command {
        Commands::Import(args) => {
            let binary_path = PathBuf::from(&args.binary);
            if !binary_path.exists() {
                anyhow::bail!("Binary not found: {}", args.binary);
            }

            let result = client
                .import_binary(
                    &args.binary,
                    args.project
                        .as_ref()
                        .unwrap_or(&"quick-analysis".to_string()),
                    args.program.as_deref(),
                )
                .await?;

            if let Some(program_name) = result.as_str() {
                println!("Successfully imported as: {}", program_name);
            } else if let Some(program_name) = result.get("program").and_then(|p| p.as_str()) {
                println!("Successfully imported as: {}", program_name);
            }

            return Ok(String::new());
        }
        Commands::Analyze(args) => {
            let config = Config::load()?;
            let program = resolve_program(&args.program, &config)?;
            let project = resolve_project(&args.project, &config, &program)?;

            println!("Analyzing {}...", program);

            client.analyze_program(&project, &program).await?;

            println!("Analysis complete!");

            return Ok(String::new());
        }
        Commands::Quick(args) => {
            let project = args
                .project
                .clone()
                .unwrap_or_else(|| "quick-analysis".to_string());
            let binary_path = PathBuf::from(&args.binary);

            println!("Quick analysis of {}...\n", args.binary);

            println!("[1/3] Importing binary...");
            let result = client.import_binary(&args.binary, &project, None).await?;

            let program_name = if let Some(name) = result.as_str() {
                name.to_string()
            } else if let Some(name) = result.get("program").and_then(|p| p.as_str()) {
                name.to_string()
            } else {
                binary_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("program")
                    .to_string()
            };

            println!("[2/3] Running analysis...");
            client.analyze_program(&project, &program_name).await?;

            println!("[3/3] Done!\n");
            println!("Analysis complete. To query the binary, start the daemon:");
            println!(
                "  ghidra daemon start --project {} --program {}",
                project, program_name
            );
            println!("\nThen run queries like:");
            println!("  ghidra function list");
            println!("  ghidra decompile main");
            println!("  ghidra summary");

            return Ok(String::new());
        }
        Commands::Query(args) => match args.data_type.as_str() {
            "functions" => {
                client
                    .list_functions(args.limit, args.filter.clone())
                    .await?
            }
            "strings" => client.list_strings(args.limit).await?,
            "imports" => client.list_imports().await?,
            "exports" => client.list_exports().await?,
            "memory" => client.memory_map().await?,
            other => anyhow::bail!("Query type '{}' not yet supported via daemon", other),
        },
        Commands::Decompile(args) => client.decompile(args.target.clone()).await?,
        Commands::Function(cmd) => {
            use cli::FunctionCommands;
            match cmd {
                FunctionCommands::List(opts) => {
                    client
                        .list_functions(opts.limit, opts.filter.clone())
                        .await?
                }
                FunctionCommands::Decompile(args) => client.decompile(args.target.clone()).await?,
                _ => anyhow::bail!("Function subcommand not yet supported via daemon"),
            }
        }
        Commands::Strings(cmd) => {
            use cli::StringsCommands;
            match cmd {
                StringsCommands::List(opts) => client.list_strings(opts.limit).await?,
                _ => anyhow::bail!("Strings subcommand not yet supported via daemon"),
            }
        }
        Commands::Memory(cmd) => {
            use cli::MemoryCommands;
            match cmd {
                MemoryCommands::Map(_) => client.memory_map().await?,
                _ => anyhow::bail!("Memory subcommand not yet supported via daemon"),
            }
        }
        Commands::Dump(cmd) => {
            use cli::DumpCommands;
            match cmd {
                DumpCommands::Imports(_) => client.list_imports().await?,
                DumpCommands::Exports(_) => client.list_exports().await?,
                DumpCommands::Functions(opts) => {
                    client
                        .list_functions(opts.limit, opts.filter.clone())
                        .await?
                }
                DumpCommands::Strings(opts) => client.list_strings(opts.limit).await?,
            }
        }
        Commands::Summary(_) => client.program_info().await?,
        Commands::XRef(cmd) => {
            use cli::XRefCommands;
            match cmd {
                XRefCommands::To(args) => client.xrefs_to(args.address.clone()).await?,
                XRefCommands::From(args) => client.xrefs_from(args.address.clone()).await?,
                XRefCommands::List(_) => anyhow::bail!("XRef list not yet supported via daemon"),
            }
        }
        // Queue commands - use dedicated IPC
        Commands::Queue(queue_cmd) => {
            use cli::QueueCommands;
            match queue_cmd {
                QueueCommands::Add(args) => {
                    // Expand globs on the client side
                    let mut paths = Vec::new();
                    for pattern in &args.patterns {
                        match glob::glob(pattern) {
                            Ok(entries) => {
                                let mut matched = false;
                                for entry in entries {
                                    match entry {
                                        Ok(path) => {
                                            if path.is_file() {
                                                let abs = if path.is_absolute() {
                                                    path
                                                } else {
                                                    std::env::current_dir()?.join(&path)
                                                };
                                                paths.push(
                                                    abs.to_string_lossy().to_string(),
                                                );
                                                matched = true;
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "Warning: error reading glob entry: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                                if !matched {
                                    eprintln!(
                                        "Warning: no files matched pattern '{}'",
                                        pattern
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "Warning: invalid glob pattern '{}': {}",
                                    pattern, e
                                );
                            }
                        }
                    }

                    if paths.is_empty() {
                        anyhow::bail!("No files matched the given pattern(s)");
                    }

                    let result = client
                        .queue_add(paths.clone(), args.project.clone())
                        .await?;
                    let added = result
                        .get("added")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("Added {} file(s) to the analysis queue", added);
                    if added < paths.len() as u64 {
                        println!(
                            "  ({} skipped as duplicates)",
                            paths.len() as u64 - added
                        );
                    }
                    return Ok(String::new());
                }
                QueueCommands::List => {
                    client.queue_list().await?
                }
                QueueCommands::Remove(args) => {
                    // Expand globs on the client side
                    let mut paths = Vec::new();
                    for pattern in &args.patterns {
                        match glob::glob(pattern) {
                            Ok(entries) => {
                                for entry in entries.flatten() {
                                    let abs = if entry.is_absolute() {
                                        entry
                                    } else {
                                        std::env::current_dir()?.join(&entry)
                                    };
                                    paths.push(abs.to_string_lossy().to_string());
                                }
                            }
                            Err(_) => {
                                // Treat as literal path if not a valid glob
                                paths.push(pattern.clone());
                            }
                        }
                    }

                    let result = client.queue_remove(paths).await?;
                    let removed = result
                        .get("removed")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    println!("Removed {} item(s) from the analysis queue", removed);
                    return Ok(String::new());
                }
                QueueCommands::Wait(args) => {
                    println!("Waiting for analysis queue to complete...");
                    let interval =
                        tokio::time::Duration::from_secs(args.interval);
                    loop {
                        let status = client.queue_status().await?;
                        let all_done = status
                            .get("all_done")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        let total = status
                            .get("total")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let completed = status
                            .get("completed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let failed = status
                            .get("failed")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let pending = status
                            .get("pending")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let analyzing = status
                            .get("analyzing")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);

                        if total == 0 {
                            println!("Queue is empty.");
                            return Ok(String::new());
                        }

                        eprint!(
                            "\r  Progress: {}/{} completed, {} failed, {} pending, {} analyzing",
                            completed, total, failed, pending, analyzing
                        );

                        if all_done {
                            eprintln!();
                            println!(
                                "All done! {} completed, {} failed out of {} total.",
                                completed, failed, total
                            );
                            return Ok(String::new());
                        }

                        tokio::time::sleep(interval).await;
                    }
                }
            }
        }
        // New commands - forward through ExecuteCli
        Commands::Symbol(_)
        | Commands::Type(_)
        | Commands::Comment(_)
        | Commands::Graph(_)
        | Commands::Find(_)
        | Commands::Diff(_)
        | Commands::Patch(_)
        | Commands::Script(_)
        | Commands::Disasm(_)
        | Commands::Batch(_)
        | Commands::Stats(_) => {
            let command_json = serde_json::to_string(command)
                .map_err(|e| anyhow::anyhow!("Failed to serialize command: {}", e))?;
            client.execute_cli_json(command_json).await?
        }
        _ => anyhow::bail!("Command not supported via daemon"),
    };

    // Determine output format based on flags and TTY detection
    let format = if pretty_flag {
        OutputFormat::Json
    } else if json_flag {
        OutputFormat::JsonCompact
    } else {
        auto_detect_format(atty::is(atty::Stream::Stdout))
    };

    // Detect if result is already an array before wrapping
    let values = match result {
        serde_json::Value::Array(arr) => arr,
        single => vec![single],
    };

    let formatter = DefaultFormatter;
    formatter.format(&values, format).map_err(Into::into)
}

/// Handle daemon management commands.
async fn handle_daemon_command(cmd: DaemonCommands) -> anyhow::Result<()> {
    match cmd {
        DaemonCommands::Start {
            project,
            program,
            port,
            foreground,
        } => handle_daemon_start(project, program, port, foreground).await,
        DaemonCommands::Stop { project } => handle_daemon_stop(project).await,
        DaemonCommands::Restart {
            project,
            program,
            port,
        } => handle_daemon_restart(project, program, port).await,
        DaemonCommands::Status { project } => handle_daemon_status(project).await,
        DaemonCommands::Ping { project } => handle_daemon_ping(project).await,
        DaemonCommands::ClearCache { project } => handle_daemon_clear_cache(project).await,
    }
}

/// Start the daemon.
async fn handle_daemon_start(
    project: Option<String>,
    program: Option<String>,
    port: Option<u16>,
    foreground: bool,
) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;
    let project_path = resolve_project_path(&project, &config)?;

    // Resolve program name
    let program_name = program.or(config.default_program.clone());

    // Check if daemon is already running
    ensure_not_running(&data_dir, &project_path)?;

    // Create log file path
    let log_file = data_dir.join("daemon.log");

    let daemon_config = DaemonConfig {
        project_path: project_path.clone(),
        ghidra_install_dir: config.ghidra_install_dir,
        log_file,
        program_name,
    };

    if foreground {
        // Run in foreground
        println!("Starting daemon in foreground mode...");
        run_daemon(daemon_config).await?;
    } else {
        // Run in background - platform-specific daemonization
        println!("Starting daemon for project: {}", project_path.display());

        #[cfg(unix)]
        {
            daemonize_unix(daemon_config, port)?;
        }

        #[cfg(windows)]
        {
            daemonize_windows(daemon_config, port)?;
        }

        println!("Daemon started successfully");
        println!("  Log file: {}", data_dir.join("daemon.log").display());
        println!("  Use 'ghidra daemon status' to check daemon status");
    }

    Ok(())
}

/// Stop the daemon.
async fn handle_daemon_stop(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        println!("Stopping daemon (PID: {})...", daemon_info.pid);

        // Connect via IPC and send shutdown (using project path for socket)
        let mut client = ipc::client::DaemonClient::connect(&project_path).await?;
        client.shutdown().await?;

        println!("Daemon stopped successfully");
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Restart the daemon.
async fn handle_daemon_restart(
    project: Option<String>,
    program: Option<String>,
    port: Option<u16>,
) -> anyhow::Result<()> {
    // Stop first
    handle_daemon_stop(project.clone()).await?;

    // Wait a moment
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Start again
    handle_daemon_start(project, program, port, false).await
}

/// Get daemon status.
async fn handle_daemon_status(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        println!("Daemon is running:");
        println!("  PID: {}", daemon_info.pid);
        println!("  Project: {}", daemon_info.project_path.display());
        println!("  Started: {}", daemon_info.started_at);
        println!("  Log file: {}", daemon_info.log_file.display());

        // Try to get detailed status from daemon via IPC
        if let Ok(mut client) = ipc::client::DaemonClient::connect(&project_path).await {
            if let Ok(status) = client.status().await {
                if let Some(bridge_running) = status.get("bridge_running").and_then(|v| v.as_bool())
                {
                    println!(
                        "  Bridge: {}",
                        if bridge_running { "running" } else { "stopped" }
                    );
                }
            }
        }
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Ping the daemon.
async fn handle_daemon_ping(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(_daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        let mut client = ipc::client::DaemonClient::connect(&project_path).await?;
        client.ping().await?;
        println!("Daemon is responsive");
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Clear daemon cache.
async fn handle_daemon_clear_cache(project: Option<String>) -> anyhow::Result<()> {
    let config = Config::load()?;
    let data_dir = get_data_dir()?;
    let project_path = resolve_project_path(&project, &config)?;

    if let Some(_daemon_info) = get_running_daemon_info(&data_dir, &project_path)? {
        // TODO: Implement cache clear via IPC
        println!("Cache clear not yet implemented via IPC");
        println!("Note: Cache will naturally expire after TTL");
    } else {
        println!("No daemon running for project: {}", project_path.display());
    }

    Ok(())
}

/// Handle the setup command - download and install Ghidra.
async fn handle_setup(args: SetupArgs) -> anyhow::Result<()> {
    println!("Ghidra Setup Wizard");
    println!("===================\n");

    // 1. Check Java
    if !args.force {
        if let Err(e) = ghidra::setup::check_java_requirement() {
            eprintln!("⚠ Java prerequisite check failed: {}", e);
            eprintln!("Ghidra requires JDK 17+. Use --force to continue anyway.");
            std::process::exit(1);
        }
    } else {
        println!("⚠ Skipping Java check (--force specified)");
    }

    // 2. Determine Install Directory
    let install_base = if let Some(d) = args.dir {
        PathBuf::from(d)
    } else {
        // Default to XDG_DATA_HOME/ghidra-cli/ghidra
        dirs::data_local_dir()
            .ok_or(anyhow::anyhow!("Could not determine data directory"))?
            .join("ghidra-cli")
            .join("ghidra")
    };

    std::fs::create_dir_all(&install_base)?;

    // 3. Install Ghidra
    println!("\nInstalling to: {}", install_base.display());
    let final_path = ghidra::setup::install_ghidra(args.version, install_base).await?;

    // 4. Install PyGhidra (required for Python scripting in Ghidra 12+)
    if let Err(e) = ghidra::setup::install_pyghidra(&final_path) {
        println!("⚠ PyGhidra setup failed: {}", e);
        println!("  Python scripting may not work. You can try running setup again.");
    }

    // 5. Update Config
    let mut config = Config::load()?;
    config.ghidra_install_dir = Some(final_path.clone());
    config.save()?;

    println!("\n✓ Success! Ghidra installed at: {}", final_path.display());
    println!("✓ Configuration updated.");

    // 6. Verify
    println!("\nVerifying installation...");
    let client = GhidraClient::new(config)?;
    if client.verify_installation().is_ok() {
        println!("✓ Verification passed!");
        println!("\nYou can now run: ghidra quick <binary>");
    } else {
        println!("⚠ Verification failed - analyzeHeadless not found");
        println!("  The installation may be incomplete.");
    }

    Ok(())
}

/// Daemonize by spawning a detached process (cross-platform).
///
/// This approach spawns a new process with --foreground flag instead of forking,
/// which avoids issues with Tokio runtime inheritance after fork.
#[cfg(unix)]
fn daemonize_unix(daemon_config: DaemonConfig, port: Option<u16>) -> anyhow::Result<()> {
    use std::fs::OpenOptions;
    use std::process::{Command, Stdio};

    let log_file_path = daemon_config.log_file.clone();

    // Open log file for stdout/stderr
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)?;

    let stdout = log_file.try_clone()?;
    let stderr = log_file;

    // Get the current executable path
    let exe_path = std::env::current_exe()?;

    // Build the command to spawn ourselves with --foreground flag
    let mut cmd = Command::new(exe_path);
    cmd.arg("daemon").arg("start").arg("--foreground");

    // Add project path
    cmd.arg("--project")
        .arg(daemon_config.project_path.to_string_lossy().to_string());

    // Add program if specified
    if let Some(program) = &daemon_config.program_name {
        cmd.arg("--program").arg(program);
    }

    // Add port if specified
    if let Some(p) = port {
        cmd.arg("--port").arg(p.to_string());
    }

    // Redirect stdout/stderr to log file, detach stdin
    cmd.stdin(Stdio::null());
    cmd.stdout(stdout);
    cmd.stderr(stderr);

    // Spawn the detached process
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn daemon process: {}", e))?;

    Ok(())
}

/// Daemonize on Windows by spawning a detached process.
#[cfg(windows)]
fn daemonize_windows(daemon_config: DaemonConfig, port: Option<u16>) -> anyhow::Result<()> {
    use std::process::Command;

    // Get the current executable path
    let exe_path = std::env::current_exe()?;

    // Build the command to spawn ourselves with --foreground flag
    let mut cmd = Command::new(exe_path);
    cmd.arg("daemon").arg("start").arg("--foreground");

    // Add project path
    cmd.arg("--project")
        .arg(daemon_config.project_path.to_string_lossy().to_string());

    // Add port if specified
    if let Some(p) = port {
        cmd.arg("--port").arg(p.to_string());
    }

    // Windows-specific: CREATE_NO_WINDOW flag
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }

    // Spawn the detached process
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn daemon process: {}", e))?;

    Ok(())
}

fn handle_init() -> anyhow::Result<()> {
    println!("Ghidra CLI Initialization");
    println!("========================\n");

    let mut config = Config::default();

    // Check if Ghidra is installed
    #[cfg(target_os = "windows")]
    {
        if let Some(dir) = Config::detect_ghidra_windows() {
            println!("Found Ghidra installation at: {}", dir.display());
            config.ghidra_install_dir = Some(dir);
        }
    }

    if config.ghidra_install_dir.is_none() {
        println!("Ghidra installation not found automatically.");
        println!("Please set GHIDRA_INSTALL_DIR environment variable or update the config file.");
        println!("\nExample:");
        println!("  set GHIDRA_INSTALL_DIR=C:\\ghidra\\ghidra_11.0");
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
            println!("✓");
            println!("  Location: {}", dir.display());

            let client = GhidraClient::new(config.clone());
            match client {
                Ok(c) => {
                    if c.verify_installation().is_ok() {
                        println!("  analyzeHeadless: ✓");
                    } else {
                        println!("  analyzeHeadless: ✗ (not found)");
                    }
                }
                Err(e) => {
                    println!("  Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("✗");
            println!("  Error: {}", e);
        }
    }

    // Check project directory
    print!("\nChecking project directory... ");
    match config.get_project_dir() {
        Ok(dir) => {
            println!("✓");
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
            println!("✗");
            println!("  Error: {}", e);
        }
    }

    // Check config file
    print!("\nConfig file... ");
    match Config::config_path() {
        Ok(path) => {
            println!("✓");
            println!("  Location: {}", path.display());
            println!("  Exists: {}", if path.exists() { "yes" } else { "no" });
        }
        Err(e) => {
            println!("✗");
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
            // Simple key-value setting (could be expanded)
            match key.as_str() {
                "default_output_format" => config.default_output_format = Some(value),
                "timeout" => {
                    let timeout: u64 = value.parse().map_err(|_| {
                        GhidraError::ConfigError("Invalid timeout value".to_string())
                    })?;
                    config.timeout = Some(timeout);
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
            let project_path = client.get_project_path(&name);
            if project_path.exists() {
                std::fs::remove_dir_all(&project_path)?;
                println!("Project '{}' deleted", name);
            } else {
                println!("Project '{}' not found", name);
            }
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

fn resolve_program(program: &Option<String>, config: &Config) -> Result<String> {
    program
        .clone()
        .or_else(|| config.get_default_program())
        .ok_or_else(|| GhidraError::Other("No program specified. Use --program or set default with 'ghidra set-default program <name>'".to_string()))
}

fn resolve_project(project: &Option<String>, config: &Config, program: &str) -> Result<String> {
    Ok(project
        .clone()
        .or_else(|| config.get_default_project())
        .unwrap_or_else(|| format!("{}-project", program)))
}

/// Resolve a project name to its full path on disk.
/// If the project name is already an absolute path, returns it as-is.
/// Otherwise, resolves relative to the configured project directory.
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
