use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "ghidra")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output JSON with pretty formatting
    #[arg(long, global = true)]
    pub pretty: bool,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    /// Universal query command for any data type
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand)]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand)]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(subcommand)]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand)]
    Type(TypeCommands),

    /// Comment operations
    #[command(subcommand)]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand)]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand)]
    Graph(GraphCommands),

    /// Decompile function
    Decompile(DecompileArgs),

    /// Disassemble code
    Disasm(DisasmArgs),

    /// Diff operations
    #[command(subcommand)]
    Diff(DiffCommands),

    /// Dump/export data
    #[command(subcommand)]
    Dump(DumpCommands),

    /// Patch binary
    #[command(subcommand)]
    Patch(PatchCommands),

    /// Script execution
    #[command(subcommand)]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Set default values
    SetDefault(SetDefaultArgs),

    /// Quick analysis (import + analyze + summary)
    Quick(QuickArgs),

    /// Program summary
    Summary(SummaryArgs),

    /// Program statistics
    Stats(StatsArgs),

    /// Show version information
    Version,

    /// Check Ghidra installation
    Doctor,

    /// Initialize configuration
    Init,

    /// Import a binary into a project
    Import(ImportArgs),

    /// Analyze a program
    Analyze(AnalyzeArgs),

    /// Daemon management commands
    #[command(subcommand)]
    Daemon(DaemonCommands),

    /// Analysis queue for batch binary processing
    #[command(subcommand)]
    Queue(QueueCommands),

    /// Download and setup Ghidra automatically
    Setup(SetupArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryArgs {
    /// Data type to query (functions, strings, imports, etc.)
    pub data_type: String,

    /// Target program
    #[arg(long, env = "GHIDRA_DEFAULT_PROGRAM")]
    pub program: Option<String>,

    /// Project name
    #[arg(long, env = "GHIDRA_DEFAULT_PROJECT")]
    pub project: Option<String>,

    /// Filter expression
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format
    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long)]
    pub sort: Option<String>,

    /// Only return count
    #[arg(long)]
    pub count: bool,

    /// Output as JSON (shorthand for --format=json)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProjectArgs {
    #[command(subcommand)]
    pub command: ProjectCommands,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProjectCommands {
    /// Create a new project
    Create { name: String },
    /// List all projects
    List,
    /// Delete a project
    Delete { name: String },
    /// Show project information
    Info { name: Option<String> },
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ProgramCommands {
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(ProgramTargetArgs),
    /// Export program
    Export(ExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ProgramTargetArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ExportArgs {
    /// Export format (xml, json, asm, c)
    pub format: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Output file
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionCommands {
    /// List all functions
    List(QueryOptions),
    /// Get function details
    Get(FunctionGetArgs),
    /// Decompile function
    Decompile(FunctionGetArgs),
    /// Disassemble function
    Disasm(FunctionGetArgs),
    /// Get function calls
    Calls(FunctionGetArgs),
    /// Get cross-references to function
    XRefs(FunctionGetArgs),
    /// Rename function
    Rename(RenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionGetArgs {
    /// Function address or name
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateFunctionArgs {
    pub address: String,
    pub name: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    List(QueryOptions),
    /// Get references to a string
    Refs(StringRefsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StringRefsArgs {
    pub string: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum SymbolCommands {
    /// List all symbols
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// Create symbol
    Create(CreateSymbolArgs),
    /// Delete symbol
    Delete(SymbolGetArgs),
    /// Rename symbol
    Rename(RenameArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SymbolGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateSymbolArgs {
    pub address: String,
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum MemoryCommands {
    /// Show memory map
    Map(QueryOptions),
    /// Read memory
    Read(MemReadArgs),
    /// Write memory
    Write(MemWriteArgs),
    /// Search memory
    Search(MemSearchArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemReadArgs {
    pub address: String,
    pub size: usize,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemWriteArgs {
    pub address: String,
    pub bytes: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct MemSearchArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum XRefCommands {
    /// Get cross-references to address
    To(XRefArgs),
    /// Get cross-references from address
    From(XRefArgs),
    /// List all cross-references
    List(XRefArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct XRefArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCommands {
    /// List data types
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create type
    Create(CreateTypeArgs),
    /// Apply type to address
    Apply(ApplyTypeArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateTypeArgs {
    pub definition: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ApplyTypeArgs {
    pub address: String,
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List all comments
    List(QueryOptions),
    /// Get comment at address
    Get(CommentGetArgs),
    /// Set comment
    Set(CommentSetArgs),
    /// Delete comment
    Delete(CommentGetArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentGetArgs {
    pub address: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CommentSetArgs {
    pub address: String,
    pub text: String,
    #[arg(long)]
    pub comment_type: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find strings
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find functions
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    Crypto(QueryOptions),
    /// Find interesting functions
    Interesting(QueryOptions),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindStringArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindBytesArgs {
    pub hex: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindFunctionArgs {
    pub pattern: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FindCallsArgs {
    pub function: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    Callers(GraphFunctionArgs),
    /// Get callees of function
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    pub function: String,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphExportArgs {
    /// Export format (e.g., dot, json)
    #[arg(id = "export_format")]
    pub format: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DecompileArgs {
    pub target: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmArgs {
    pub address: String,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DiffCommands {
    /// Compare two programs
    Programs(DiffProgramsArgs),
    /// Compare functions
    Functions(DiffFunctionsArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffProgramsArgs {
    pub program1: String,
    pub program2: String,
    #[arg(long)]
    pub format: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffFunctionsArgs {
    /// First function (name or address)
    pub func1: String,
    /// Second function (name or address)
    pub func2: String,
    #[arg(long)]
    pub format: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DumpCommands {
    /// Dump imports
    Imports(QueryOptions),
    /// Dump exports
    Exports(QueryOptions),
    /// Dump functions
    Functions(QueryOptions),
    /// Dump strings
    Strings(QueryOptions),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum PatchCommands {
    /// Patch bytes
    Bytes(PatchBytesArgs),
    /// NOP instructions
    Nop(PatchNopArgs),
    /// Export patched binary
    Export(PatchExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchBytesArgs {
    pub address: String,
    pub hex: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchNopArgs {
    pub address: String,
    #[arg(long)]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct PatchExportArgs {
    #[arg(short, long)]
    pub output: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ScriptCommands {
    /// Run a script file
    Run(ScriptRunArgs),
    /// Execute inline Python code
    Python(ScriptInlineArgs),
    /// Execute inline Java code
    Java(ScriptInlineArgs),
    /// List available scripts
    List,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptRunArgs {
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Script arguments (after --)
    #[arg(last = true)]
    pub args: Vec<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptInlineArgs {
    pub code: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct BatchArgs {
    pub script_file: String,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum ConfigCommands {
    /// List all configuration
    List,
    /// Get configuration value
    Get { key: String },
    /// Set configuration value
    Set { key: String, value: String },
    /// Reset configuration
    Reset,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetDefaultArgs {
    pub kind: String,
    pub value: String,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QuickArgs {
    pub binary: String,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct StatsArgs {
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ImportArgs {
    pub binary: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

/// Common query options used across commands
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryOptions {
    #[arg(long)]
    pub program: Option<String>,

    #[arg(long)]
    pub project: Option<String>,

    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub fields: Option<String>,

    #[arg(long, short = 'o')]
    pub format: Option<String>,

    #[arg(long)]
    pub limit: Option<usize>,

    #[arg(long)]
    pub offset: Option<usize>,

    #[arg(long)]
    pub sort: Option<String>,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub json: bool,
}

/// Daemon management commands
#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum DaemonCommands {
    /// Start the daemon
    Start {
        /// Project path
        #[arg(long)]
        project: Option<String>,

        /// Program name to load
        #[arg(long)]
        program: Option<String>,

        /// Port to listen on (default: auto-select)
        #[arg(long)]
        port: Option<u16>,

        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the daemon
    Stop {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Restart the daemon
    Restart {
        /// Project path
        #[arg(long)]
        project: Option<String>,

        /// Program name to load
        #[arg(long)]
        program: Option<String>,

        /// Port to listen on (default: auto-select)
        #[arg(long)]
        port: Option<u16>,
    },

    /// Get daemon status
    Status {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Ping the daemon
    Ping {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Clear the cache
    ClearCache {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },
}

/// Analysis queue commands for batch binary processing
#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum QueueCommands {
    /// Add binaries matching a glob pattern to the analysis queue
    Add(QueueAddArgs),

    /// List all items in the analysis queue
    List,

    /// Remove items matching a glob pattern from the queue
    Remove(QueueRemoveArgs),

    /// Block until all queued analyses are complete
    Wait(QueueWaitArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueueAddArgs {
    /// Glob pattern(s) matching binaries to analyze (e.g. "./bins/*" or "/usr/bin/ls")
    #[arg(required = true)]
    pub patterns: Vec<String>,

    /// Project name for imported binaries
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueueRemoveArgs {
    /// Glob pattern(s) matching queued paths to remove
    #[arg(required = true)]
    pub patterns: Vec<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueueWaitArgs {
    /// Poll interval in seconds (default: 2)
    #[arg(long, default_value = "2")]
    pub interval: u64,
}

/// Arguments for the setup command
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetupArgs {
    /// Specific Ghidra version to install (e.g., "11.0"). Defaults to latest.
    #[arg(long)]
    pub version: Option<String>,

    /// Installation directory. Defaults to standard data directory.
    #[arg(long, short = 'd')]
    pub dir: Option<String>,

    /// Skip Java check
    #[arg(long)]
    pub force: bool,
}
