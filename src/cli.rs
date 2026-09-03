use clap::{ArgAction, Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

#[derive(Parser)]
#[command(name = "ghidra")]
#[command(version, about = "Rust CLI for Ghidra reverse engineering", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Increase log verbosity printed to stdout (-v=warn, -vv=info, -vvv=debug)
    #[arg(short, long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress non-essential output
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,

    /// Output JSON with pretty formatting
    #[arg(long, global = true)]
    pub pretty: bool,

    /// Project name or path (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub project: Option<String>,

    /// Program name within the project (can also be specified per-subcommand)
    #[arg(long, global = true)]
    pub program: Option<String>,

    /// Directory under which Ghidra projects are stored.
    /// Overrides config `ghidra_project_dir` and the default location.
    /// Note: Ghidra 12.1+ rejects paths containing a dot-prefixed component.
    #[arg(long, global = true)]
    pub projects_dir: Option<std::path::PathBuf>,

    /// Full JDK home for Ghidra to use (must be a JDK, not a JRE).
    /// Overrides config `java_home` and auto-detection.
    #[arg(long, global = true)]
    pub java_home: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum Commands {
    /// Universal query command for any data type
    Query(QueryArgs),

    /// Project management commands
    Project(ProjectArgs),

    /// Program/binary management commands
    #[command(subcommand, alias = "prog", alias = "programs")]
    Program(ProgramCommands),

    /// Function operations
    #[command(subcommand, alias = "fn", alias = "func", alias = "functions")]
    Function(FunctionCommands),

    /// String operations
    #[command(subcommand, alias = "string", alias = "str")]
    Strings(StringsCommands),

    /// Symbol operations
    #[command(subcommand, alias = "sym", alias = "symbols")]
    Symbol(SymbolCommands),

    /// Memory operations
    #[command(subcommand, alias = "mem")]
    Memory(MemoryCommands),

    /// Cross-reference operations
    #[command(
        subcommand,
        alias = "xrefs",
        alias = "xref",
        alias = "crossref",
        alias = "crossrefs"
    )]
    XRef(XRefCommands),

    /// Type operations
    #[command(subcommand, alias = "types")]
    Type(TypeCommands),

    /// Function tag operations
    #[command(subcommand, alias = "tags")]
    Tag(TagCommands),

    /// Comment operations
    #[command(subcommand, alias = "comments")]
    Comment(CommentCommands),

    /// Search operations
    #[command(subcommand, alias = "search")]
    Find(FindCommands),

    /// Graph operations
    #[command(subcommand, alias = "callgraph", alias = "cg")]
    Graph(GraphCommands),

    /// Decompile function
    #[command(alias = "decomp", alias = "dec")]
    Decompile(DecompileArgs),

    /// Disassemble code
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(DisasmArgs),

    /// Disassemble at an address, disassembling first if nothing is there yet
    /// (the common case for computed-jump targets auto-analysis never reached)
    #[command(alias = "disassemble-at")]
    DisasmAt(DisasmAtArgs),

    /// Clear code units in a range (undoes auto-analysis that mis-disassembled
    /// through inline data), optionally re-disassembling at a precise address
    Clear(ClearArgs),

    /// Diff operations
    #[command(subcommand)]
    Diff(DiffCommands),

    /// Dump/export data
    #[command(subcommand, alias = "export")]
    Dump(DumpCommands),

    /// Patch binary
    #[command(subcommand)]
    Patch(PatchCommands),

    /// Script execution
    #[command(subcommand, alias = "scripts")]
    Script(ScriptCommands),

    /// Batch operations
    Batch(BatchArgs),

    /// Configuration management
    #[command(subcommand)]
    Config(ConfigCommands),

    /// Set default values
    SetDefault(SetDefaultArgs),

    /// Program summary
    #[command(alias = "info")]
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
    #[command(alias = "analysis")]
    Analyze(AnalyzeArgs),

    /// Start the bridge
    Start {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Stop the bridge
    Stop {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Restart the bridge
    Restart {
        /// Project path
        #[arg(long)]
        project: Option<String>,
        /// Program name to load
        #[arg(long)]
        program: Option<String>,
    },

    /// Show bridge status
    Status {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Ping the bridge
    Ping {
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// List active, queued, and recently completed bridge jobs
    Jobs {
        /// Show one job by ID; omit for the bridge queue and recent jobs
        job_id: Option<u64>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Request cooperative cancellation of a bridge job (defaults to active job)
    Cancel {
        /// Job ID; omit to cancel the currently active job
        job_id: Option<u64>,
        /// Project path
        #[arg(long)]
        project: Option<String>,
    },

    /// Download and setup Ghidra automatically
    Setup(SetupArgs),

    /// Rename a symbol (shortcut for `symbol rename`)
    #[command(alias = "mv")]
    Rename(RenameArgs),
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

    /// Filter expression: <field><op><value>, e.g. 'name~PK' (contains),
    /// 'name=~"^PK_"' (regex), 'size>100'. Ops: = != > >= < <= ~ ^ $ =~.
    /// Combine with AND/OR/NOT. Bare words are rejected.
    #[arg(short, long)]
    pub filter: Option<String>,

    /// Field selection (comma-separated)
    #[arg(long)]
    pub fields: Option<String>,

    /// Output format
    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results (0 = unlimited; default 1000)
    #[arg(long)]
    pub limit: Option<usize>,

    /// Skip first N results
    #[arg(long)]
    pub offset: Option<usize>,

    /// Sort by field(s) (comma-separated, prefix with - for descending)
    #[arg(long, allow_hyphen_values = true)]
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
    /// List all programs in the project
    #[command(alias = "ls")]
    List(ProgramTargetArgs),
    /// Open/switch to a program
    Open(ProgramTargetArgs),
    /// Close a program
    Close(ProgramTargetArgs),
    /// Delete a program
    Delete(ProgramTargetArgs),
    /// Show program information
    Info(ProgramTargetArgs),
    /// Export program
    Export(ExportArgs),
    /// Flush pending changes to disk so the Ghidra GUI (or a fresh bridge)
    /// can see them. The bridge cannot save in place while it keeps running
    /// — Ghidra's headless script-execution harness holds its own
    /// transaction open for the bridge's whole lifetime, so this stops and
    /// immediately restarts the bridge (a few seconds of downtime) rather
    /// than failing outright. Every write command — rename, comment, patch,
    /// type/symbol/tag ops — stays in the bridge's memory, invisible to the
    /// GUI and lost if the bridge dies uncleanly, until either this or
    /// `ghidra stop` runs.
    Save(ProgramTargetArgs),
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
    #[command(alias = "ls")]
    List(FunctionListArgs),
    /// Get function details
    #[command(alias = "show", alias = "detail")]
    Get(FunctionGetArgs),
    /// Decompile function
    #[command(alias = "decomp")]
    Decompile(FunctionDecompileArgs),
    /// Disassemble function
    #[command(alias = "disassemble", alias = "dis")]
    Disasm(FunctionGetArgs),
    /// Get function calls
    Calls(FunctionGetArgs),
    /// Get cross-references to function
    #[command(alias = "xrefs", alias = "crossrefs", alias = "references")]
    XRefs(FunctionGetArgs),
    /// Rename function
    Rename(RenameArgs),
    /// Create function
    Create(CreateFunctionArgs),
    /// Delete function
    Delete(FunctionGetArgs),
    /// Set function signature from C-style string
    SetSignature(SetSignatureArgs),
    /// Set function return type
    SetReturnType(SetReturnTypeArgs),
    /// Set function calling convention
    SetCallingConvention(SetCallingConventionArgs),
    /// Set variable type in a function
    SetVarType(SetVarTypeArgs),
    /// Mark a function as never returning to its call site (fixes bogus
    /// decompiled fallthrough tails at every call site in one shot)
    #[command(name = "set-noreturn")]
    SetNoReturn(SetNoReturnArgs),
    /// Function tag operations (subsystem/module grouping)
    #[command(subcommand)]
    Tag(FunctionTagCommands),
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FunctionTagCommands {
    /// Add a tag to a function
    Add(FunctionTagArgs),
    /// Remove a tag from a function
    Remove(FunctionTagArgs),
    /// List tags on a function, or every tag definition in the program
    List(FunctionTagListArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionTagArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    pub target: String,
    /// Tag name
    pub tag_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionTagListArgs {
    /// Function target; omit to list every tag definition in the program
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetNoReturnArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Set to false to clear a previously-set no-return flag
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub value: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetNoReturnArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionListArgs {
    /// Only functions carrying this tag (repeatable; multiple tags = AND)
    #[arg(long = "tag", value_name = "NAME")]
    pub tags: Vec<String>,
    /// Only functions with no tags
    #[arg(long, conflicts_with = "tags")]
    pub untagged: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionGetArgs {
    /// Function target (name/address/FUN_...)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FunctionGetArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct RenameArgs {
    pub old_name: String,
    pub new_name: String,
    /// Address of the specific symbol to rename. Required when `old_name`
    /// is shared by more than one symbol -- Ghidra reuses auto-generated
    /// names (`caseD_XX`, `LAB_XXXX`, ...) across unrelated addresses
    /// program-wide, so a bare name alone is not a safe rename target.
    #[arg(long)]
    pub address: Option<String>,
    /// Filter expression (same syntax as `--filter` on query commands) used
    /// to narrow which of the name's matches get renamed, e.g.
    /// `--filter 'address=0xc200'`.
    #[arg(short, long)]
    pub filter: Option<String>,
    /// Rename every symbol named `old_name`, program-wide. Without this (or
    /// `--address`/`--filter`), an ambiguous name is a hard error rather
    /// than silently renaming every match.
    #[arg(long)]
    pub all: bool,
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

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct FunctionDecompileArgs {
    /// Function target (name/address/FUN_...)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FunctionDecompileArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetSignatureArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// C-style signature string, e.g. "int main(int argc, char** argv)"
    #[arg(long)]
    pub signature: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetSignatureArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetReturnTypeArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Return type name
    #[arg(long = "type")]
    pub return_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetReturnTypeArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetCallingConventionArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Calling convention name (e.g., "__cdecl", "__stdcall", "__fastcall")
    #[arg(long)]
    pub convention: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetCallingConventionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct SetVarTypeArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Variable name to retype
    #[arg(long = "var")]
    pub var_name: String,
    /// New type name (e.g., "int", "char *", "MyStruct")
    #[arg(long = "type")]
    pub type_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

impl SetVarTypeArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum StringsCommands {
    /// List all strings
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get references to a string
    #[command(alias = "references", alias = "xrefs")]
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
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get symbol details
    Get(SymbolGetArgs),
    /// Create symbol
    Create(CreateSymbolArgs),
    /// Delete symbol
    Delete(SymbolDeleteArgs),
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
pub struct SymbolDeleteArgs {
    pub name: String,
    /// Address of the specific symbol to delete. Required when `name` is
    /// shared by more than one symbol -- Ghidra reuses auto-generated names
    /// (`caseD_XX`, `LAB_XXXX`, ...) across unrelated addresses
    /// program-wide, so a bare name alone is not a safe delete target.
    #[arg(long)]
    pub address: Option<String>,
    /// Delete every symbol named `name`, program-wide. Without this (or
    /// `--address`/`--filter`), an ambiguous name is a hard error rather
    /// than silently deleting every match.
    #[arg(long)]
    pub all: bool,
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
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// XRef target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl XRefArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TypeCommands {
    /// List data types
    #[command(alias = "ls")]
    List(QueryOptions),
    /// Get type definition
    Get(TypeGetArgs),
    /// Create type
    Create(CreateTypeArgs),
    /// Apply type to address
    Apply(ApplyTypeArgs),
    /// Delete a data type
    #[command(alias = "rm")]
    Delete(TypeDeleteArgs),
    /// Rename a data type
    #[command(alias = "mv")]
    Rename(TypeRenameArgs),
    /// Create an enum type
    CreateEnum(CreateEnumArgs),
    /// Create a typedef (type alias)
    Typedef(TypedefArgs),
    /// Add a field to a struct type
    AddField(TypeAddFieldArgs),
    /// Remove a field from a struct type
    DelField(TypeDelFieldArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeGetArgs {
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateTypeArgs {
    /// Bare identifier for the new (empty) struct type -- NOT a C-style
    /// struct definition. Build fields afterward with `type add-field`.
    #[arg(value_name = "NAME")]
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
    /// Clear any conflicting data unit first instead of failing on it
    #[arg(long, alias = "clear-conflicting")]
    pub force: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDeleteArgs {
    /// Name or path of the type to delete
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeRenameArgs {
    /// Current name of the type
    pub old_name: String,
    /// New name for the type
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct CreateEnumArgs {
    /// Enum type name
    pub name: String,
    /// Comma-separated KEY=VALUE pairs, e.g. "RED=0,GREEN=1,BLUE=2"
    #[arg(long)]
    pub values: String,
    /// Size in bytes (1, 2, 4, or 8)
    #[arg(long, default_value = "4")]
    pub size: i32,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypedefArgs {
    /// Name for the new typedef
    pub name: String,
    /// Base type to alias (e.g., "int", "dword", "MyStruct")
    pub base_type: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeAddFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name
    #[arg(long)]
    pub name: String,
    /// Field type (e.g., "int", "byte", "pointer", a custom struct name)
    #[arg(long = "type")]
    pub field_type: String,
    /// Offset within the struct (if omitted, appends at end)
    #[arg(long)]
    pub offset: Option<i32>,
    /// Field size override
    #[arg(long)]
    pub size: Option<i32>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TypeDelFieldArgs {
    /// Name of the struct type to modify
    pub type_name: String,
    /// Field name to remove
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum TagCommands {
    /// List all function tags (or one function's tags with --function)
    #[command(alias = "ls")]
    List(TagListArgs),
    /// Show the functions carrying a tag
    #[command(alias = "show")]
    Get(TagGetArgs),
    /// Create a function tag
    Create(TagCreateArgs),
    /// Delete a tag (detaches it from all functions)
    #[command(alias = "rm")]
    Delete(TagDeleteArgs),
    /// Rename a tag everywhere it is used
    #[command(alias = "mv")]
    Rename(TagRenameArgs),
    /// Set or clear a tag's comment ("" clears)
    SetComment(TagSetCommentArgs),
    /// Attach tags to a function (auto-creates missing tags)
    Add(TagAttachArgs),
    /// Detach tags from a function
    Remove(TagDetachArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagListArgs {
    /// Only tags attached to this function (name | 0xaddr | FUN_<hex>)
    #[arg(long = "function", value_name = "TARGET")]
    pub function: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagGetArgs {
    /// Tag name (case-sensitive)
    pub name: String,
    #[command(flatten)]
    pub options: QueryOptions,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagCreateArgs {
    /// Tag name (case-sensitive; commas and semicolons not allowed)
    pub name: String,
    /// Optional comment describing the tag's meaning
    #[arg(long)]
    pub comment: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDeleteArgs {
    /// Tag name
    pub name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagRenameArgs {
    /// Current tag name
    pub old_name: String,
    /// New tag name
    pub new_name: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagSetCommentArgs {
    /// Tag name
    pub name: String,
    /// New comment text; empty string clears the comment
    pub comment: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagAttachArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// One or more tag names to attach
    // `required = true` is mandatory: num_args = 1.. alone does NOT make a
    // positional required — `ghidra tag add crypto` would parse with the tag
    // name consumed as TARGET and an empty tag list.
    #[arg(value_name = "TAG", required = true, num_args = 1..)]
    pub tags: Vec<String>,
    /// Error instead of auto-creating tags that don't exist yet
    #[arg(long)]
    pub no_create: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct TagDetachArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET")]
    pub target: String,
    /// Tag names to detach
    #[arg(value_name = "TAG", num_args = 0.., required_unless_present = "all")]
    pub tags: Vec<String>,
    /// Detach every tag from the function
    #[arg(long, conflicts_with = "tags")]
    pub all: bool,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum CommentCommands {
    /// List all comments
    #[command(alias = "ls")]
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
    /// Comment text. Omit when using --stdin or --text-file: a shell argument
    /// is subject to shell metacharacter expansion (e.g. backticks) before
    /// ghidra-cli ever sees it, which can silently corrupt free-form prose.
    #[arg(required_unless_present_any = ["stdin", "text_file"])]
    pub text: Option<String>,
    #[arg(long)]
    pub comment_type: Option<String>,
    /// Read comment text from stdin instead of the TEXT argument
    #[arg(long, conflicts_with_all = ["text", "text_file"])]
    pub stdin: bool,
    /// Read comment text from a file instead of the TEXT argument
    #[arg(long, conflicts_with = "text")]
    pub text_file: Option<std::path::PathBuf>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum FindCommands {
    /// Find strings
    #[command(alias = "str", alias = "strings")]
    String(FindStringArgs),
    /// Find byte patterns
    Bytes(FindBytesArgs),
    /// Find functions
    #[command(alias = "func", alias = "fn", alias = "functions")]
    Function(FindFunctionArgs),
    /// Find calls to function
    Calls(FindCallsArgs),
    /// Find crypto constants
    #[command(alias = "encryption")]
    Crypto(QueryOptions),
    /// Find interesting functions
    #[command(alias = "suspicious", alias = "notable")]
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
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl FindCallsArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Subcommand, Clone, Serialize, Deserialize, Debug)]
pub enum GraphCommands {
    /// Call graph
    Calls(QueryOptions),
    /// Get callers of function
    #[command(alias = "called-by", alias = "incoming")]
    Callers(GraphFunctionArgs),
    /// Get callees of function
    #[command(alias = "calls-to", alias = "outgoing")]
    Callees(GraphFunctionArgs),
    /// Export graph
    Export(GraphExportArgs),
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct GraphFunctionArgs {
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    #[arg(long)]
    pub depth: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl GraphFunctionArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
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
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Function target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Include local variable details (name, type, storage)
    #[arg(long)]
    pub with_vars: bool,
    /// Include parameter details (name, type, storage)
    #[arg(long)]
    pub with_params: bool,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DecompileArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmArgs {
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(value_name = "TARGET", required_unless_present = "target")]
    pub positional_target: Option<String>,
    /// Disassembly target (name | 0xaddr | FUN_<hex>)
    #[arg(long = "target", value_name = "TARGET")]
    pub target: Option<String>,
    /// Number of instructions to disassemble
    #[arg(long = "instructions", short = 'n')]
    pub num_instructions: Option<usize>,
    #[command(flatten)]
    pub options: QueryOptions,
}

impl DisasmArgs {
    pub fn resolved_target(&self) -> &str {
        self.target
            .as_deref()
            .or(self.positional_target.as_deref())
            .expect("clap should ensure target is provided")
    }
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DisasmAtArgs {
    /// Address to disassemble at
    pub address: String,
    /// Number of instructions to report back once disassembled
    #[arg(long = "count", short = 'n')]
    pub count: Option<usize>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ClearArgs {
    /// Address range to clear, as START:END (e.g. 0bf3:0bfa)
    pub range: String,
    /// Clear only, leaving the range as undefined data (no redisassembly)
    #[arg(long, conflicts_with = "disasm_at")]
    pub to_data: bool,
    /// Re-disassemble at this address immediately after clearing
    #[arg(long)]
    pub disasm_at: Option<String>,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
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
    #[arg(long)]
    pub project: Option<String>,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct DiffFunctionsArgs {
    /// First function (name or address)
    pub func1: String,
    /// Second function (name or address)
    pub func2: String,
    #[arg(long)]
    pub format: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
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
    /// Run a script file (pass "-" to read Java source from stdin instead of a path)
    Run(ScriptRunArgs),
    /// Disabled by design: use `script run -` (stdin) for a Python-authored
    /// one-off ported to Java, or `script run PATH` for a checked-in file.
    /// See `ghidra doctor` for why inline eval isn't offered as a shortcut.
    Python(ScriptInlineArgs),
    /// Disabled by design: use `script run -` to pipe Java source on stdin
    /// instead -- it goes through the same compile/execute path as a file on
    /// disk rather than a second, less-sandboxed eval path. See `ghidra doctor`.
    Java(ScriptInlineArgs),
    /// List available scripts
    List,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct ScriptRunArgs {
    /// Path to a script file, or "-" to read Java source from stdin
    pub script_path: String,
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Expected output artifact: PATH or PATH:MIN_ROWS (repeatable). The job
    /// fails if the artifact is missing, empty, or below MIN_ROWS.
    #[arg(long = "expect", value_name = "PATH[:MIN_ROWS]")]
    pub expect: Vec<String>,
    /// Allow an expected artifact to exist but be empty.
    #[arg(long)]
    pub allow_empty: bool,
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

    #[arg(long)]
    pub project: Option<String>,

    #[arg(long)]
    pub program: Option<String>,
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
    /// Import only — skip auto-analysis (the program is still persisted)
    #[arg(long, default_value = "false")]
    pub no_analyze: bool,
    /// Return immediately, let bridge continue import in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct AnalyzeArgs {
    #[arg(long)]
    pub program: Option<String>,
    #[arg(long)]
    pub project: Option<String>,
    /// Return immediately, let bridge continue analysis in background
    #[arg(long, default_value = "false")]
    pub detach: bool,
}

/// Common query options used across commands
#[derive(Args, Clone, Serialize, Deserialize, Debug)]
pub struct QueryOptions {
    #[arg(long)]
    pub program: Option<String>,

    #[arg(long)]
    pub project: Option<String>,

    /// Filter expression: <field><op><value>, e.g. 'name~PK' (contains),
    /// 'name=~"^PK_"' (regex), 'size>100'. Ops: = != > >= < <= ~ ^ $ =~.
    /// Combine with AND/OR/NOT. Bare words are rejected.
    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(long)]
    pub fields: Option<String>,

    #[arg(long, short = 'o')]
    pub format: Option<String>,

    /// Maximum number of results (0 = unlimited; default 1000)
    #[arg(long)]
    pub limit: Option<usize>,

    #[arg(long)]
    pub offset: Option<usize>,

    #[arg(long, allow_hyphen_values = true)]
    pub sort: Option<String>,

    #[arg(long)]
    pub count: bool,

    #[arg(long)]
    pub json: bool,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decompile_target_flag() {
        let cli = Cli::try_parse_from(["ghidra", "decompile", "--target", "FUN_00401000"])
            .expect("decompile --target should parse");
        match cli.command {
            Commands::Decompile(args) => assert_eq!(args.resolved_target(), "FUN_00401000"),
            _ => panic!("expected decompile command"),
        }
    }

    #[test]
    fn parses_function_get_positional_target() {
        let cli = Cli::try_parse_from(["ghidra", "function", "get", "main"])
            .expect("function get positional target should parse");
        match cli.command {
            Commands::Function(FunctionCommands::Get(args)) => {
                assert_eq!(args.resolved_target(), "main");
            }
            _ => panic!("expected function get command"),
        }
    }
}
