// Ghidra CLI Bridge - TCP socket server for CLI commands
// @category Bridge
// @keybinding
// @menupath Tools.Start CLI Bridge
// @toolbar
//
// Single-file GhidraScript that runs a persistent TCP server inside Ghidra
// to serve CLI commands. Replaces the Python bridge.py with a pure Java
// implementation using Ghidra's bundled Gson for JSON serialization.

import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraState;
import ghidra.util.exception.CancelledException;
// org.osgi.framework is the OSGi core framework API, exported to every
// bundle unconditionally (unlike Ghidra-internal packages such as
// ghidra.app.plugin.core.osgi, which the bridge's own bundle cannot wire --
// see handleScriptRun()). Safe to import directly.
import org.osgi.framework.Bundle;
import generic.jar.ResourceFile;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.*;
import java.security.MessageDigest;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Iterator;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class GhidraCliBridge extends GhidraScript {

    private static final int MAX_PROGRAM_QUEUE = 256;
    private static final int MAX_CLIENT_THREADS = 32;
    private static final int MAX_PENDING_CLIENTS = 128;
    private static final int MAX_RESPONSE_THREADS = 16;
    private static final int MAX_RETAINED_JOBS = 100;
    private static final int MAX_STATUS_JOBS = 25;

    private final Gson gson = new GsonBuilder().serializeNulls().create();
    private final Object lifecycleLock = new Object();
    private final BlockingQueue<ProgramJob> programQueue =
        new ArrayBlockingQueue<>(MAX_PROGRAM_QUEUE);
    private final ConcurrentHashMap<Long, JobRecord> jobs = new ConcurrentHashMap<>();
    private final ConcurrentLinkedDeque<Long> completedJobIds = new ConcurrentLinkedDeque<>();
    private final AtomicLong nextJobId = new AtomicLong(1);
    private final AtomicLong nextClientThreadId = new AtomicLong(1);
    private final AtomicLong nextResponseThreadId = new AtomicLong(1);

    private volatile long startTime;
    private volatile boolean acceptingJobs;
    private volatile boolean shutdownRequested;
    private volatile ServerSocket serverSocket;
    private volatile ExecutorService connectionExecutor;
    private volatile ExecutorService responseExecutor;
    private volatile JobRecord activeJob;
    private volatile Thread programThread;

    // Immutable bridge-info values published by the program execution thread.
    // Control-plane threads read these instead of dereferencing Ghidra objects.
    private volatile String currentProgramNameSnapshot;
    private volatile String projectNameSnapshot;
    private volatile int programCountSnapshot;

    private static final Pattern NAMED_HEX_ADDRESS_PATTERN =
        Pattern.compile("(?i)^(?:FUN|SUB|LAB|DAT)_([0-9a-f]+)$");

    private static class JobTaskMonitor extends TaskMonitorAdapter {
        private volatile String message = "";
        private volatile long progress;
        private volatile long maximum;
        private volatile boolean indeterminate;

        JobTaskMonitor() {
            super(true);
        }

        @Override
        public void setMessage(String value) {
            message = value == null ? "" : value;
            super.setMessage(value);
        }

        @Override
        public String getMessage() {
            return message;
        }

        @Override
        public void setProgress(long value) {
            progress = value;
            super.setProgress(value);
        }

        @Override
        public long getProgress() {
            return progress;
        }

        @Override
        public void initialize(long value) {
            maximum = value;
            progress = 0;
            super.initialize(value);
        }

        @Override
        public void setMaximum(long value) {
            maximum = value;
            super.setMaximum(value);
        }

        @Override
        public long getMaximum() {
            return maximum;
        }

        @Override
        public void setIndeterminate(boolean value) {
            indeterminate = value;
            super.setIndeterminate(value);
        }

        @Override
        public boolean isIndeterminate() {
            return indeterminate;
        }

        @Override
        public void incrementProgress(long amount) {
            progress += amount;
            super.incrementProgress(amount);
        }
    }

    private static class JobRecord {
        final long id;
        final String command;
        final long enqueuedAt;
        final JobTaskMonitor monitor = new JobTaskMonitor();
        final CompletableFuture<HandleResult> completion = new CompletableFuture<>();

        volatile String state = "queued";
        volatile long startedAt;
        volatile long finishedAt;
        volatile String error;

        JobRecord(long id, String command) {
            this.id = id;
            this.command = command;
            this.enqueuedAt = System.currentTimeMillis();
        }
    }

    private static class ProgramJob {
        final JobRecord record;
        final JsonObject args;
        final boolean poison;

        ProgramJob(JobRecord record, JsonObject args) {
            this(record, args, false);
        }

        private ProgramJob(JobRecord record, JsonObject args, boolean poison) {
            this.record = record;
            this.args = args;
            this.poison = poison;
        }

        static ProgramJob poison() {
            return new ProgramJob(null, null, true);
        }
    }

    @Override
    public void run() throws Exception {
        startTime = System.currentTimeMillis();
        // Get port file path from script arguments
        String[] scriptArgs = getScriptArgs();
        if (scriptArgs.length < 1) {
            printerr("Usage: GhidraCliBridge.java <port_file_path>");
            return;
        }
        String portFilePath = scriptArgs[0];

        // Bind to dynamic port on localhost only. Socket handling happens on
        // separate threads; this original GhidraScript thread remains the sole
        // executor for operations that dereference currentProgram/state.
        serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        int port = serverSocket.getLocalPort();

        connectionExecutor = new ThreadPoolExecutor(
            MAX_CLIENT_THREADS,
            MAX_CLIENT_THREADS,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(MAX_PENDING_CLIENTS),
            runnable -> {
                Thread thread = new Thread(
                    runnable,
                    "ghidra-cli-client-" + nextClientThreadId.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());

        responseExecutor = new ThreadPoolExecutor(
            4,
            MAX_RESPONSE_THREADS,
            60L,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(MAX_PROGRAM_QUEUE),
            runnable -> {
                Thread thread = new Thread(
                    runnable,
                    "ghidra-cli-response-" + nextResponseThreadId.getAndIncrement());
                thread.setDaemon(true);
                return thread;
            },
            new ThreadPoolExecutor.AbortPolicy());

        acceptingJobs = true;
        shutdownRequested = false;
        programThread = Thread.currentThread();
        refreshBridgeSnapshot();

        // Write port file
        File portFile = new File(portFilePath);
        portFile.getParentFile().mkdirs();
        try (PrintWriter pw = new PrintWriter(new FileWriter(portFile))) {
            pw.println(port);
        }

        // Write PID file
        String pidFilePath = portFilePath.replaceAll("\\.port$", ".pid");
        File pidFile = new File(pidFilePath);
        try (PrintWriter pw = new PrintWriter(new FileWriter(pidFile))) {
            pw.println(ProcessHandle.current().pid());
        }

        // Signal ready to parent process
        println("---GHIDRA_CLI_START---");
        JsonObject readyMsg = new JsonObject();
        readyMsg.addProperty("status", "ready");
        readyMsg.addProperty("port", port);
        println(gson.toJson(readyMsg));
        println("---GHIDRA_CLI_END---");
        System.out.flush();

        Thread acceptor = new Thread(this::acceptClients, "ghidra-cli-acceptor");
        acceptor.setDaemon(true);
        acceptor.start();

        try {
            // Deliberately run program jobs on the original GhidraScript thread.
            // Communications remain responsive while Ghidra access stays serialized.
            runProgramJobs();
        } finally {
            // No explicit currentProgram.save() here: it always fails with
            // "Unable to lock due to active transaction" for as long as this
            // postScript keeps running (Ghidra's headless script-execution
            // harness holds its own outer transaction open for the whole
            // life of the script -- confirmed empirically, not something we
            // can end from in here). Persistence instead happens once run()
            // returns and control passes back to that harness: its own
            // per-program completion (import/-process's normal "save and
            // release" step) is what actually flushes pending changes to
            // disk, which is why a clean `ghidra stop` persists everything
            // and a mid-session save cannot. See `ghidra program save`
            // (Rust side): it gets a real flush by stopping and restarting
            // the bridge rather than trying to save in place.
            //
            // CRITICAL INVARIANT, learned the hard way: because that outer
            // transaction stays open for this entire run(), every handler's
            // `currentProgram.startTransaction()` below is a *nested*
            // sub-transaction of it (Ghidra's DomainObjectDBTransaction just
            // adds an entry to the one already-open transaction rather than
            // starting an independent one). Ghidra's transaction manager
            // tracks a single ABORTED/COMMITTED status for the whole nest:
            // if ANY nested entry ends with `endTransaction(id, false)`, the
            // entire group's status latches to ABORTED, and when the
            // outermost entry (this run()'s own, closed by the harness after
            // we return) finally closes, Ghidra rolls back *everything*
            // since the bridge started -- not just the one failed handler.
            // This previously caused silent, total loss of an entire
            // session's mutations (renames, comments, new functions, all of
            // it) whenever a single handled/expected error occurred anywhere
            // in the session, with zero indication at save time. So: no
            // handler below may ever call `endTransaction(txId, false)`.
            // On a handler-level failure, still commit `true` -- at worst
            // that leaves a harmless partial side effect (e.g. a stray
            // auto-disassembly from an aborted create_function), which is
            // vastly preferable to losing every other already-"successful"
            // change made since the bridge came up.
            beginShutdown();
            try {
                acceptor.join(5000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            ExecutorService executor = connectionExecutor;
            if (executor != null) {
                executor.shutdown();
                try {
                    if (!executor.awaitTermination(30, TimeUnit.SECONDS)) {
                        executor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    executor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            ExecutorService responses = responseExecutor;
            if (responses != null) {
                responses.shutdown();
                try {
                    if (!responses.awaitTermination(30, TimeUnit.SECONDS)) {
                        responses.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    responses.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            // Leave port/pid files for the Rust CLI to clean up. Deleting them
            // here races the JVM's project close and lock release.
            closeServerSocket();
        }
    }

    private void acceptClients() {
        try {
            while (!shutdownRequested) {
                Socket client = serverSocket.accept();
                try {
                    connectionExecutor.execute(() -> serveClient(client));
                } catch (RejectedExecutionException e) {
                    rejectClient(client, "Bridge has too many concurrent clients; retry shortly");
                }
            }
        } catch (SocketException e) {
            if (!shutdownRequested) {
                printerr("Accept error: " + e.getMessage());
                beginShutdown();
            }
        } catch (IOException e) {
            if (!shutdownRequested) {
                printerr("Accept error: " + e.getMessage());
                beginShutdown();
            }
        } finally {
            ExecutorService executor = connectionExecutor;
            if (executor != null) {
                executor.shutdown();
            }
        }
    }

    private void serveClient(Socket client) {
        try {
            // The wire protocol is one JSON request per connection. Parse and
            // enqueue here, but never occupy a connection thread while waiting
            // for serialized Ghidra work to finish.
            client.setSoTimeout(30000);
            BufferedReader in = new BufferedReader(
                new InputStreamReader(client.getInputStream()));
            String line = in.readLine();
            if (line == null || line.trim().isEmpty()) {
                client.close();
                return;
            }

            CompletableFuture<HandleResult> completion = handleRequest(line.trim());
            if (completion.isDone()) {
                respondAndClose(client, completion.join());
                return;
            }

            completion.whenComplete((result, error) -> {
                HandleResult response = result;
                if (error != null) {
                    Throwable cause = error.getCause() == null ? error : error.getCause();
                    response = new HandleResult(errorResponse(cause.getMessage()), false);
                }
                final HandleResult completedResponse = response;
                try {
                    responseExecutor.execute(
                        () -> respondAndClose(client, completedResponse));
                } catch (RejectedExecutionException e) {
                    try {
                        client.close();
                    } catch (IOException ignored) {
                        // The client may already have disconnected.
                    }
                }
            });
        } catch (IOException e) {
            try {
                client.close();
            } catch (IOException ignored) {
                // Already closed.
            }
            if (!shutdownRequested) {
                printerr("Client error: " + e.getMessage());
            }
        }
    }

    private void respondAndClose(Socket client, HandleResult result) {
        try (
            Socket closeableClient = client;
            PrintWriter out = new PrintWriter(
                new OutputStreamWriter(closeableClient.getOutputStream()), true)
        ) {
            out.println(gson.toJson(result.response));
            out.flush();
        } catch (IOException e) {
            if (!shutdownRequested) {
                printerr("Client response error: " + e.getMessage());
            }
        }
    }

    private void rejectClient(Socket client, String message) {
        try (
            Socket closeableClient = client;
            PrintWriter out = new PrintWriter(
                new OutputStreamWriter(closeableClient.getOutputStream()), true)
        ) {
            out.println(gson.toJson(errorResponse(message)));
        } catch (IOException ignored) {
            // The client may already have disconnected.
        }
    }

    private void runProgramJobs() {
        while (true) {
            ProgramJob job;
            try {
                job = programQueue.take();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                beginShutdown();
                return;
            }

            if (job.poison) {
                return;
            }
            executeProgramJob(job);
        }
    }

    private void executeProgramJob(ProgramJob job) {
        JobRecord record = job.record;
        TaskMonitor bridgeMonitor = monitor;
        activeJob = record;
        record.state = "running";
        record.startedAt = System.currentTimeMillis();
        monitor = record.monitor;

        HandleResult result;
        try {
            result = executeProgramRequest(record.command, job.args);
            result.response.addProperty("job_id", record.id);

            String responseStatus = result.response.has("status")
                ? result.response.get("status").getAsString()
                : "error";
            if (record.monitor.isCancelled()) {
                record.state = "error".equals(responseStatus)
                    ? "cancelled"
                    : "completed_after_cancel";
            } else {
                record.state = "error".equals(responseStatus) ? "failed" : "complete";
            }
            if ("error".equals(responseStatus) && result.response.has("message")) {
                record.error = result.response.get("message").getAsString();
            }
        } catch (Exception e) {
            record.state = record.monitor.isCancelled() ? "cancelled" : "failed";
            record.error = e.getMessage();
            result = new HandleResult(errorResponse(e.getMessage()), false);
            result.response.addProperty("job_id", record.id);
        } finally {
            monitor = bridgeMonitor;
            record.finishedAt = System.currentTimeMillis();
            activeJob = null;
            refreshBridgeSnapshot();
        }

        record.completion.complete(result);
        retainCompletedJob(record.id);
    }

    private void beginShutdown() {
        ServerSocket socketToClose;
        boolean enqueuePoison = false;
        synchronized (lifecycleLock) {
            if (shutdownRequested) {
                return;
            }
            shutdownRequested = true;
            acceptingJobs = false;
            socketToClose = serverSocket;
            if (Thread.currentThread() != programThread) {
                enqueuePoison = true;
            }
        }

        if (socketToClose != null) {
            try {
                socketToClose.close();
            } catch (IOException ignored) {
                // Already closed.
            }
        }

        if (enqueuePoison) {
            // FIFO placement drains every job accepted before shutdown. Preserve
            // interruption but do not strand the GhidraScript thread without its
            // shutdown sentinel if the bounded queue is temporarily full.
            boolean interrupted = false;
            while (true) {
                try {
                    programQueue.put(ProgramJob.poison());
                    break;
                } catch (InterruptedException e) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private void closeServerSocket() {
        ServerSocket socket = serverSocket;
        if (socket != null && !socket.isClosed()) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // Best-effort cleanup during JVM teardown.
            }
        }
    }

    // --- Request Handling ---

    private static class HandleResult {
        JsonObject response;
        boolean shouldShutdown;

        HandleResult(JsonObject response, boolean shouldShutdown) {
            this.response = response;
            this.shouldShutdown = shouldShutdown;
        }
    }

    private CompletableFuture<HandleResult> handleRequest(String line) {
        try {
            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
            String command = req.has("command") ? req.get("command").getAsString() : null;
            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                ? req.getAsJsonObject("args") : new JsonObject();

            if (command == null || command.isEmpty()) {
                return CompletableFuture.completedFuture(
                    new HandleResult(errorResponse("Command required"), false));
            }

            if (isControlCommand(command)) {
                return CompletableFuture.completedFuture(handleControlCommand(command, args));
            }

            JobRecord record = new JobRecord(nextJobId.getAndIncrement(), command);
            ProgramJob job = new ProgramJob(record, args.deepCopy());

            synchronized (lifecycleLock) {
                if (!acceptingJobs) {
                    return CompletableFuture.completedFuture(new HandleResult(
                        errorResponse("Bridge is draining and is not accepting new program jobs"),
                        false));
                }
                jobs.put(record.id, record);
                if (!programQueue.offer(job)) {
                    jobs.remove(record.id);
                    return CompletableFuture.completedFuture(new HandleResult(
                        errorResponse("Bridge program queue is full; retry shortly"), false));
                }
            }
            return record.completion;
        } catch (Exception e) {
            return CompletableFuture.completedFuture(
                new HandleResult(errorResponse(e.getMessage()), false));
        }
    }

    private boolean isControlCommand(String command) {
        switch (command) {
            case "ping":
            case "status":
            case "bridge_info":
            case "job_status":
            case "job_cancel":
            case "shutdown":
                return true;
            default:
                return false;
        }
    }

    private HandleResult handleControlCommand(String command, JsonObject args) {
        switch (command) {
            case "ping":
                return new HandleResult(successResponse(handlePing()), false);
            case "status":
                return new HandleResult(successResponse(handleStatus()), false);
            case "bridge_info":
                return new HandleResult(successResponse(handleBridgeInfo()), false);
            case "job_status":
                return new HandleResult(successResponse(handleJobStatus(args)), false);
            case "job_cancel": {
                JsonObject result = handleJobCancel(args);
                if (result.has("error")) {
                    return new HandleResult(
                        errorResponse(result.get("error").getAsString()), false);
                }
                return new HandleResult(successResponse(result), false);
            }
            case "shutdown": {
                beginShutdown();
                JsonObject response = new JsonObject();
                response.addProperty("status", "shutdown");
                response.addProperty("mode", "drain");
                return new HandleResult(response, true);
            }
            default:
                return new HandleResult(errorResponse("Unknown control command: " + command), false);
        }
    }

    private HandleResult executeProgramRequest(String command, JsonObject args) {
        try {
            JsonObject result = dispatchCommand(command, args);
            if (result == null) {
                return new HandleResult(errorResponse("Unknown command: " + command), false);
            }

            if (result.has("error")) {
                JsonObject detail = (result.has("detail") && result.get("detail").isJsonObject())
                    ? result.getAsJsonObject("detail") : null;
                return new HandleResult(
                    errorResponse(result.get("error").getAsString(), detail), false);
            }

            return new HandleResult(successResponse(result), false);
        } catch (Exception e) {
            return new HandleResult(errorResponse(e.getMessage()), false);
        }
    }

    private JsonObject dispatchCommand(String command, JsonObject args) {
        if (command == null) return null;
        switch (command) {
            case "program_info":    return handleProgramInfo();
            case "list_functions":  return handleListFunctions(args);
            case "get_function":    return handleGetFunction(args);
            case "rename_function": return handleRenameFunction(args);
            case "create_function": return handleCreateFunction(args);
            case "delete_function": return handleDeleteFunction(args);
            case "decompile":       return handleDecompile(args);
            case "list_strings":    return handleListStrings(args);
            case "list_imports":    return handleListImports();
            case "list_exports":    return handleListExports();
            case "memory_map":      return handleMemoryMap();
            case "xrefs_to":        return handleXrefsTo(args);
            case "xrefs_from":      return handleXrefsFrom(args);
            case "xrefs_list":      return handleXrefsList(args);
            case "import":          return handleImport(args);
            case "analyze":         return handleAnalyze(args);
            case "list_programs":   return handleListPrograms();
            case "open_program":    return handleOpenProgram(args);
            case "program_close":   return handleProgramClose();
            case "program_delete":  return handleProgramDelete(args);
            case "program_export":  return handleProgramExport(args);
            // Find commands
            case "find_string":     return handleFindString(args);
            case "find_bytes":      return handleFindBytes(args);
            case "find_function":   return handleFindFunction(args);
            case "find_calls":      return handleFindCalls(args);
            case "find_crypto":     return handleFindCrypto();
            case "find_interesting": return handleFindInteresting();
            // Symbol commands
            case "symbol_list":     return handleSymbolList(args);
            case "symbol_get":      return handleSymbolGet(args);
            case "symbol_create":   return handleSymbolCreate(args);
            case "symbol_delete":   return handleSymbolDelete(args);
            case "symbol_rename":   return handleSymbolRename(args);
            // Type commands
            case "type_list":       return handleTypeList(args);
            case "type_get":        return handleTypeGet(args);
            case "type_create":     return handleTypeCreate(args);
            case "type_apply":      return handleTypeApply(args);
            case "type_delete":     return handleTypeDelete(args);
            case "type_rename":     return handleTypeRename(args);
            case "type_create_enum": return handleTypeCreateEnum(args);
            case "type_typedef":    return handleTypeTypedef(args);
            case "type_add_field":  return handleTypeAddField(args);
            case "type_del_field":  return handleTypeDelField(args);
            // Tag commands
            case "tag_list":        return handleTagList(args);
            case "tag_get":         return handleTagGet(args);
            case "tag_create":      return handleTagCreate(args);
            case "tag_delete":      return handleTagDelete(args);
            case "tag_rename":      return handleTagRename(args);
            case "tag_set_comment": return handleTagSetComment(args);
            case "tag_add":         return handleTagAdd(args);
            case "tag_remove":      return handleTagRemove(args);
            // Function signature commands
            case "function_set_signature": return handleFunctionSetSignature(args);
            case "function_set_return_type": return handleFunctionSetReturnType(args);
            case "function_set_calling_convention": return handleFunctionSetCallingConvention(args);
            case "function_set_noreturn": return handleFunctionSetNoReturn(args);
            case "function_tag_add":    return handleFunctionTagAdd(args);
            case "function_tag_remove": return handleFunctionTagRemove(args);
            case "function_tag_list":   return handleFunctionTagList(args);
            case "set_var_type":    return handleSetVarType(args);
            // Comment commands
            case "comment_list":    return handleCommentList(args);
            case "comment_get":     return handleCommentGet(args);
            case "comment_set":     return handleCommentSet(args);
            case "comment_delete":  return handleCommentDelete(args);
            // Graph commands
            case "graph_calls":     return handleGraphCalls(args);
            case "graph_callers":   return handleGraphCallers(args);
            case "graph_callees":   return handleGraphCallees(args);
            case "graph_export":    return handleGraphExport(args);
            // Diff commands
            case "diff_programs":   return handleDiffPrograms(args);
            case "diff_functions":  return handleDiffFunctions(args);
            // Patch commands
            case "patch_bytes":     return handlePatchBytes(args);
            case "patch_nop":       return handlePatchNop(args);
            case "patch_export":    return handlePatchExport(args);
            // Other commands
            case "disasm":          return handleDisasm(args);
            case "disasm_at":       return handleDisasmAt(args);
            case "clear_range":     return handleClearRange(args);
            case "stats":           return handleStats();
            // Script commands
            case "script_run":      return handleScriptRun(args);
            case "script_java":     return handleScriptJava(args);
            case "script_python":   return handleScriptPython(args);
            case "script_list":     return handleScriptList();
            // Batch
            case "batch":           return handleBatch(args);
            // Memory read
            case "read_memory":     return handleReadMemory(args);
            default:                return null;
        }
    }

    // --- Response Helpers ---

    private JsonObject successResponse(JsonObject data) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "success");
        resp.add("data", data);
        return resp;
    }

    private JsonObject errorResponse(String message) {
        return errorResponse(message, null);
    }

    /**
     * Error response carrying structured detail (e.g. a conflicting code
     * unit's type/range, or a containing function's name/entry/size) alongside
     * the message, so callers can act on it without a follow-up round trip.
     */
    private JsonObject errorResponse(String message, JsonObject detail) {
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "error");
        resp.addProperty("message", message);
        if (detail != null) {
            resp.add("detail", detail);
        }
        return resp;
    }

    private JsonObject errorResult(String message) {
        JsonObject result = new JsonObject();
        result.addProperty("error", message);
        return result;
    }

    // --- Address Resolution ---

    private Address resolveAddress(String addrStr) {
        if (currentProgram == null || addrStr == null || addrStr.isEmpty()) {
            return null;
        }

        String target = addrStr.trim();
        AddressFactory af = currentProgram.getAddressFactory();

        // Try as hex address first (with and without 0x prefix)
        Address addr = af.getAddress(target);
        if (addr != null) {
            return addr;
        }
        if (target.startsWith("0x") || target.startsWith("0X")) {
            addr = af.getAddress(target.substring(2));
            if (addr != null) {
                return addr;
            }
        }

        // Parse common Ghidra auto names like FUN_00401234 as raw addresses.
        Matcher namedHex = NAMED_HEX_ADDRESS_PATTERN.matcher(target);
        if (namedHex.matches()) {
            String hexPart = namedHex.group(1);
            addr = af.getAddress(hexPart);
            if (addr == null) {
                addr = af.getAddress("0x" + hexPart);
            }
            if (addr != null) {
                return addr;
            }
        }

        // Try as symbol/function name via SymbolTable
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator syms = st.getSymbols(target);
        while (syms.hasNext()) {
            Symbol sym = syms.next();
            Address symAddr = sym.getAddress();
            // Skip external/fake addresses - prefer real addresses
            if (symAddr != null && !symAddr.isExternalAddress()) {
                return symAddr;
            }
        }

        // Try global symbols (may include exports)
        List<Symbol> globalSyms = st.getGlobalSymbols(target);
        for (Symbol sym : globalSyms) {
            Address symAddr = sym.getAddress();
            if (symAddr != null && !symAddr.isExternalAddress()) {
                return symAddr;
            }
        }

        // Fallback: scan functions by name (O(n) but handles edge cases)
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(target)) {
                return func.getEntryPoint();
            }
        }

        return null;
    }

    // --- Helper to safely get string from JsonObject ---

    private String getArgString(JsonObject args, String key) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return null;
        return args.get(key).getAsString();
    }

    private int getArgInt(JsonObject args, String key, int defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsInt();
    }

    private boolean getArgBool(JsonObject args, String key, boolean defaultVal) {
        if (args == null || !args.has(key) || args.get(key).isJsonNull()) return defaultVal;
        return args.get(key).getAsBoolean();
    }

    private String[] getArgStringArray(JsonObject args, String key) {
        if (args == null || !args.has(key) || !args.get(key).isJsonArray()) return new String[0];
        JsonArray arr = args.getAsJsonArray(key);
        String[] out = new String[arr.size()];
        for (int i = 0; i < arr.size(); i++) out[i] = arr.get(i).getAsString();
        return out;
    }

    private JsonArray toJsonArray(String[] values) {
        JsonArray arr = new JsonArray();
        for (String v : values) arr.add(v);
        return arr;
    }

    // --- Command Handlers (M1: Core) ---

    private JsonObject handlePing() {
        JsonObject result = new JsonObject();
        result.addProperty("message", "pong");
        result.addProperty("bridge_state", acceptingJobs ? "running" : "draining");
        result.addProperty("queue_depth", programQueue.size());
        JobRecord active = activeJob;
        if (active != null) {
            result.addProperty("active_job_id", active.id);
            result.addProperty("active_command", active.command);
        }
        return result;
    }

    private JsonObject handleBridgeInfo() {
        JsonObject result = new JsonObject();
        String programName = currentProgramNameSnapshot;
        result.addProperty("protocol_version", 2);
        result.addProperty("has_current_program", programName != null);
        if (programName != null) {
            result.addProperty("current_program", programName);
        }
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        if (projectNameSnapshot != null) {
            result.addProperty("project_name", projectNameSnapshot);
        }
        result.addProperty("program_count", programCountSnapshot);
        addQueueSummary(result, false);
        return result;
    }

    private JsonObject handleStatus() {
        JsonObject result = new JsonObject();
        result.addProperty("protocol_version", 2);
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);
        addQueueSummary(result, true);
        return result;
    }

    private JsonObject handleJobStatus(JsonObject args) {
        if (args != null && args.has("job_id") && !args.get("job_id").isJsonNull()) {
            long id = args.get("job_id").getAsLong();
            JobRecord record = jobs.get(id);
            if (record == null) {
                JsonObject result = new JsonObject();
                result.addProperty("found", false);
                result.addProperty("job_id", id);
                return result;
            }
            JsonObject result = new JsonObject();
            result.addProperty("found", true);
            result.add("job", jobToJson(record, queuePosition(id)));
            return result;
        }
        return handleStatus();
    }

    private JsonObject handleJobCancel(JsonObject args) {
        JobRecord target;
        if (args != null && args.has("job_id") && !args.get("job_id").isJsonNull()) {
            target = jobs.get(args.get("job_id").getAsLong());
        } else {
            target = activeJob;
        }

        if (target == null) {
            return errorResult("No matching active or queued job");
        }

        JobRecord active = activeJob;
        if (active != null && active.id == target.id) {
            target.state = "cancel_requested";
            target.monitor.cancel();
            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", "Cancellation requested; completion is cooperative");
            return result;
        }

        ProgramJob queued = findQueuedJob(target.id);
        if (queued != null && programQueue.remove(queued)) {
            target.monitor.cancel();
            target.state = "cancelled";
            target.finishedAt = System.currentTimeMillis();
            target.error = "Cancelled before execution";
            JsonObject response = errorResponse(target.error);
            response.addProperty("job_id", target.id);
            target.completion.complete(new HandleResult(response, false));
            retainCompletedJob(target.id);

            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", target.error);
            return result;
        }

        // It may have moved from the queue to active between the checks above.
        active = activeJob;
        if (active != null && active.id == target.id) {
            target.state = "cancel_requested";
            target.monitor.cancel();
            JsonObject result = new JsonObject();
            result.addProperty("job_id", target.id);
            result.addProperty("state", target.state);
            result.addProperty("message", "Cancellation requested; completion is cooperative");
            return result;
        }

        JsonObject result = new JsonObject();
        result.addProperty("job_id", target.id);
        result.addProperty("state", target.state);
        result.addProperty("message", "Job is no longer cancellable");
        return result;
    }

    private ProgramJob findQueuedJob(long id) {
        for (ProgramJob job : programQueue) {
            if (!job.poison && job.record != null && job.record.id == id) {
                return job;
            }
        }
        return null;
    }

    private int queuePosition(long id) {
        int position = 0;
        for (ProgramJob job : programQueue) {
            if (job.poison) continue;
            if (job.record != null && job.record.id == id) {
                return position;
            }
            position++;
        }
        return -1;
    }

    private void addQueueSummary(JsonObject result, boolean includeJobs) {
        result.addProperty("bridge_state", acceptingJobs ? "running" : "draining");
        result.addProperty("accepting_jobs", acceptingJobs);
        result.addProperty("shutdown_requested", shutdownRequested);
        result.addProperty("queue_depth", queuedJobCount());

        JobRecord active = activeJob;
        if (active == null) {
            result.add("active_job", JsonNull.INSTANCE);
        } else {
            result.add("active_job", jobToJson(active, -1));
        }

        if (!includeJobs) return;

        JsonArray queued = new JsonArray();
        int position = 0;
        for (ProgramJob job : programQueue) {
            if (job.poison || job.record == null) continue;
            if (queued.size() >= MAX_STATUS_JOBS) break;
            queued.add(jobToJson(job.record, position++));
        }
        result.add("queued_jobs", queued);

        JsonArray recent = new JsonArray();
        Iterator<Long> ids = completedJobIds.descendingIterator();
        while (ids.hasNext() && recent.size() < MAX_STATUS_JOBS) {
            JobRecord record = jobs.get(ids.next());
            if (record != null) {
                recent.add(jobToJson(record, -1));
            }
        }
        result.add("recent_jobs", recent);
    }

    private int queuedJobCount() {
        int count = 0;
        for (ProgramJob job : programQueue) {
            if (!job.poison) count++;
        }
        return count;
    }

    private JsonObject jobToJson(JobRecord record, int queuePosition) {
        JsonObject result = new JsonObject();
        result.addProperty("id", record.id);
        result.addProperty("command", record.command);
        result.addProperty("state", record.state);
        result.addProperty("enqueued_at_ms", record.enqueuedAt);
        if (record.startedAt > 0) result.addProperty("started_at_ms", record.startedAt);
        if (record.finishedAt > 0) result.addProperty("finished_at_ms", record.finishedAt);
        long end = record.finishedAt > 0 ? record.finishedAt : System.currentTimeMillis();
        long start = record.startedAt > 0 ? record.startedAt : record.enqueuedAt;
        result.addProperty("elapsed_ms", Math.max(0, end - start));
        if (queuePosition >= 0) result.addProperty("queue_position", queuePosition);
        result.addProperty("cancel_requested", record.monitor.isCancelled());
        result.addProperty("cancel_enabled", record.monitor.isCancelEnabled());
        result.addProperty("progress", record.monitor.getProgress());
        result.addProperty("maximum", record.monitor.getMaximum());
        result.addProperty("indeterminate", record.monitor.isIndeterminate());
        String message = record.monitor.getMessage();
        if (message != null && !message.isEmpty()) result.addProperty("progress_message", message);
        if (record.error != null) result.addProperty("error", record.error);
        return result;
    }

    private void retainCompletedJob(long id) {
        completedJobIds.addLast(id);
        while (completedJobIds.size() > MAX_RETAINED_JOBS) {
            Long expired = completedJobIds.pollFirst();
            if (expired != null) jobs.remove(expired);
        }
    }

    private void refreshBridgeSnapshot() {
        Program program = currentProgram;
        currentProgramNameSnapshot = program == null ? null : program.getName();

        Project project = state == null ? null : state.getProject();
        projectNameSnapshot = project == null ? null : project.getName();
        programCountSnapshot = 0;
        if (project != null) {
            try {
                ProjectData projectData = project.getProjectData();
                DomainFolder rootFolder = projectData.getRootFolder();
                programCountSnapshot = rootFolder.getFiles().length;
            } catch (Exception ignored) {
                programCountSnapshot = 0;
            }
        }
    }

    private JsonObject handleProgramInfo() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonObject result = new JsonObject();
        result.addProperty("name", currentProgram.getName());
        result.addProperty("executable_path", currentProgram.getExecutablePath());
        result.addProperty("executable_format", currentProgram.getExecutableFormat());
        String compiler = currentProgram.getCompiler();
        if (compiler != null && !compiler.isEmpty()) {
            result.addProperty("compiler", compiler);
        } else {
            result.add("compiler", JsonNull.INSTANCE);
        }
        result.addProperty("language", currentProgram.getLanguage().toString());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.addProperty("min_address", currentProgram.getMinAddress().toString());
        result.addProperty("max_address", currentProgram.getMaxAddress().toString());

        FunctionManager fm = currentProgram.getFunctionManager();
        result.addProperty("function_count", fm.getFunctionCount());

        return result;
    }

    private JsonObject handleListFunctions(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");
        String[] tagFilterNames = getArgStringArray(args, "tags");
        boolean untagged = getArgBool(args, "untagged", false);

        FunctionManager fm = currentProgram.getFunctionManager();

        // Resolve tag filter up front: unknown tag is an error, not an empty result
        // (a typo must not read as "no matches").
        Set<FunctionTag> requiredTags = new HashSet<>();
        if (tagFilterNames.length > 0) {
            FunctionTagManager tm = fm.getFunctionTagManager();
            for (String tagName : tagFilterNames) {
                FunctionTag tag = tm.getFunctionTag(tagName);
                if (tag == null) return errorResult(tagNotFoundError(tagName, tm));
                requiredTags.add(tag);
            }
        }

        JsonArray functions = new JsonArray();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Function func = iter.next();
            String name = func.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }
            if (!requiredTags.isEmpty() && !func.getTags().containsAll(requiredTags)) {
                continue;
            }
            if (untagged && !func.getTags().isEmpty()) {
                continue;
            }

            JsonObject funcData = new JsonObject();
            funcData.addProperty("name", name);
            funcData.addProperty("address", func.getEntryPoint().toString());
            funcData.addProperty("size", func.getBody().getNumAddresses());
            funcData.addProperty("entry_point", func.getEntryPoint().toString());
            funcData.add("tags", functionTagNames(func));

            String sig = null;
            try {
                sig = func.getPrototypeString(false, false);
            } catch (Exception e) {
                // ignore
            }
            if (sig != null) {
                funcData.addProperty("signature", sig);
            } else {
                funcData.add("signature", JsonNull.INSTANCE);
            }

            functions.add(functionToJson(func));
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    private JsonObject functionToJson(Function func) {
        JsonObject funcData = new JsonObject();
        funcData.addProperty("name", func.getName());
        funcData.addProperty("address", func.getEntryPoint().toString());
        funcData.addProperty("size", func.getBody().getNumAddresses());
        funcData.addProperty("entry_point", func.getEntryPoint().toString());
        funcData.add("tags", functionTagNames(func));

        String sig = null;
        try {
            sig = func.getPrototypeString(false, false);
        } catch (Exception e) {
            // ignore
        }
        if (sig != null) {
            funcData.addProperty("signature", sig);
        } else {
            funcData.add("signature", JsonNull.INSTANCE);
        }

        funcData.addProperty("calling_convention", func.getCallingConventionName());
        funcData.addProperty("no_return", func.hasNoReturn());

        String comment = func.getComment();
        if (comment != null) {
            funcData.addProperty("comment", comment);
        } else {
            funcData.add("comment", JsonNull.INSTANCE);
        }

        return funcData;
    }

    private String buildFunctionTargetHint(String target) {
        if (currentProgram == null || target == null || target.isEmpty()) {
            return "Function not found";
        }

        String query = target.toLowerCase();
        List<String> containsMatches = new ArrayList<>();
        List<String> fuzzyMatches = new ArrayList<>();
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);

        while (iter.hasNext()) {
            Function func = iter.next();
            String name = func.getName();
            String lname = name.toLowerCase();

            if (lname.contains(query)) {
                containsMatches.add(name);
            } else if (query.length() >= 3 && levenshteinDistance(lname, query) <= 3) {
                fuzzyMatches.add(name);
            }
        }

        Collections.sort(containsMatches);
        Collections.sort(fuzzyMatches);

        List<String> suggestions = new ArrayList<>();
        for (String name : containsMatches) {
            suggestions.add(name);
            if (suggestions.size() >= 5) break;
        }
        if (suggestions.size() < 5) {
            for (String name : fuzzyMatches) {
                if (!suggestions.contains(name)) suggestions.add(name);
                if (suggestions.size() >= 5) break;
            }
        }

        StringBuilder hint = new StringBuilder();
        hint.append("Cannot resolve function target: ").append(target)
            .append(". Try: ghidra function list --filter ").append(target);
        if (!suggestions.isEmpty()) {
            hint.append(". Closest matches: ").append(String.join(", ", suggestions));
        }
        return hint.toString();
    }

    private int levenshteinDistance(String a, String b) {
        int n = a.length();
        int m = b.length();
        int[][] dp = new int[n + 1][m + 1];

        for (int i = 0; i <= n; i++) dp[i][0] = i;
        for (int j = 0; j <= m; j++) dp[0][j] = j;

        for (int i = 1; i <= n; i++) {
            for (int j = 1; j <= m; j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(
                    Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                    dp[i - 1][j - 1] + cost
                );
            }
        }
        return dp[n][m];
    }

    private JsonObject handleGetFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        Address addr = resolveAddress(target);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(target));
        }

        Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at target " + target + ". Try: ghidra function list --filter " + target);
        }
        return functionToJson(func);
    }

    private JsonObject handleRenameFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String oldTarget = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        String addressArg = getArgString(args, "address");
        if (oldTarget == null || newName == null || oldTarget.isEmpty() || newName.isEmpty()) {
            return errorResult("old_name and new_name required");
        }

        try {
            Function func;
            if (addressArg != null && !addressArg.isEmpty()) {
                // Scope the rename to the function whose entry point is exactly
                // this address, rather than resolving old_name program-wide --
                // Ghidra reuses auto-generated names (caseD_XX, LAB_XXXX, ...)
                // across unrelated addresses.
                Address addr = resolveAddress(addressArg);
                if (addr == null) {
                    return errorResult("Invalid address: " + addressArg);
                }
                func = currentProgram.getFunctionManager().getFunctionAt(addr);
                if (func == null) {
                    return errorResult("No function at address " + addressArg);
                }
                if (!func.getName().equals(oldTarget)) {
                    return errorResult("Function at address " + addressArg + " is named '"
                        + func.getName() + "', not '" + oldTarget + "'");
                }
            } else {
                func = findFunctionByNameOrAddress(oldTarget);
                if (func == null) {
                    return errorResult(buildFunctionTargetHint(oldTarget));
                }
            }

            int txId = currentProgram.startTransaction("Rename function");
            try {
                String oldName = func.getName();
                func.setName(newName, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "renamed");
                result.addProperty("old_name", oldName);
                result.addProperty("new_name", newName);
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to rename function: " + e.getMessage());
        }
    }

    private JsonObject handleCreateFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        String requestedName = getArgString(args, "name");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            Address addr = resolveAddress(target);
            if (addr == null) {
                return errorResult("Invalid function target: " + target + ". Expected address/symbol/FUN_<hex>.");
            }

            FunctionManager fm = currentProgram.getFunctionManager();
            Function owner = fm.getFunctionContaining(addr);
            if (owner != null) {
                return functionAlreadyExistsError(addr, owner);
            }

            String functionName = (requestedName == null || requestedName.isEmpty())
                ? ("FUN_" + addr.toString().replace(":", ""))
                : requestedName;

            Listing listing = currentProgram.getListing();
            boolean autoDisassembled = false;

            int txId = currentProgram.startTransaction("Create function");
            try {
                // The most common reason createFunction rejects an address: no
                // instruction has been disassembled there yet (static auto-analysis
                // never reached it, e.g. a computed-jump table target). Disassemble
                // first rather than making the caller do it via a separate command.
                if (listing.getInstructionAt(addr) == null) {
                    autoDisassembled = disassemble(addr);
                }

                Function created;
                try {
                    // FunctionManager.createFunction(..., body=null, ...) does not compute a
                    // body by following flow from the entry point -- for many perfectly valid
                    // entry points (notably ARM/Thumb vtable targets never reached by static
                    // auto-analysis) it deterministically rejects the address with "Function
                    // body must contain the entrypoint". CreateFunctionCmd is what
                    // GhidraScript.createFunction()/the UI's "Create Function" action use: it
                    // follows flow from the entry point to compute a correct body first.
                    ghidra.app.cmd.function.CreateFunctionCmd cmd =
                        new ghidra.app.cmd.function.CreateFunctionCmd(
                            functionName, addr, null, SourceType.USER_DEFINED);
                    boolean ok = cmd.applyTo(currentProgram, monitor);
                    if (!ok) {
                        currentProgram.endTransaction(txId, true);
                        return diagnoseCreateFunctionFailure(addr, autoDisassembled, cmd.getStatusMsg());
                    }
                    created = fm.getFunctionAt(addr);
                } catch (Exception e) {
                    // CreateFunctionCmd rejects some addresses by throwing rather than
                    // returning false -- run it through the same diagnosis either way instead
                    // of losing the detail to the generic catch below.
                    currentProgram.endTransaction(txId, true);
                    return diagnoseCreateFunctionFailure(addr, autoDisassembled, e.getMessage());
                }
                if (created == null) {
                    currentProgram.endTransaction(txId, true);
                    return diagnoseCreateFunctionFailure(addr, autoDisassembled, null);
                }
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", created.getName());
                result.addProperty("address", created.getEntryPoint().toString());
                if (autoDisassembled) result.addProperty("auto_disassembled", true);
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to create function: " + e.getMessage());
        }
    }

    /** Structured "already claimed" error: who owns the address, so callers can decide without a follow-up lookup. */
    private JsonObject functionAlreadyExistsError(Address addr, Function owner) {
        JsonObject detail = new JsonObject();
        detail.addProperty("name", owner.getName());
        detail.addProperty("entry_point", owner.getEntryPoint().toString());
        detail.addProperty("size", owner.getBody().getNumAddresses());
        JsonObject err = errorResult("Function already exists at " + addr.toString()
            + ": address is inside " + owner.getName() + "@" + owner.getEntryPoint()
            + " (size " + owner.getBody().getNumAddresses() + " bytes)");
        err.add("detail", detail);
        return err;
    }

    /**
     * fm.createFunction returning null carries no reason from Ghidra itself.
     * Check the likely causes ourselves (no instruction landed, address already
     * inside another function's body from a shared-code tail jump, boundary not
     * on a code unit start) so the error distinguishes them instead of
     * collapsing to one generic message.
     */
    private JsonObject diagnoseCreateFunctionFailure(Address addr, boolean autoDisassembled, String thrownMessage) {
        Listing listing = currentProgram.getListing();
        List<String> reasons = new ArrayList<>();
        JsonObject detail = new JsonObject();
        detail.addProperty("address", addr.toString());
        detail.addProperty("auto_disassembled_attempted", autoDisassembled);
        if (thrownMessage != null) {
            detail.addProperty("ghidra_exception", thrownMessage);
        }

        boolean hasInstruction = listing.getInstructionAt(addr) != null;
        detail.addProperty("has_instruction_at_entry", hasInstruction);
        if (!hasInstruction) {
            reasons.add("no instruction landed at entry point even after a disassemble attempt "
                + "(address may be data, mid-instruction, or in an unmapped memory block)");
        }

        Function owner = currentProgram.getFunctionManager().getFunctionContaining(addr);
        if (owner != null) {
            detail.addProperty("containing_function", owner.getName());
            detail.addProperty("containing_function_entry", owner.getEntryPoint().toString());
            detail.addProperty("containing_function_size", owner.getBody().getNumAddresses());
            reasons.add("address is already inside existing function " + owner.getName()
                + "@" + owner.getEntryPoint() + " (likely shared code reached by a tail jump, "
                + "not a call) -- consider `symbol create` for a label instead of a new function");
        }

        CodeUnit cu = listing.getCodeUnitContaining(addr);
        if (cu != null) {
            detail.addProperty("code_unit_range", cu.getMinAddress() + "-" + cu.getMaxAddress());
            detail.addProperty("code_unit_is_instruction", cu instanceof Instruction);
            if (!cu.getMinAddress().equals(addr)) {
                reasons.add("address " + addr + " is mid-code-unit, not the start of "
                    + cu.getMinAddress() + "-" + cu.getMaxAddress());
            }
        }

        if (reasons.isEmpty()) {
            reasons.add(thrownMessage != null
                ? "Ghidra rejected the entry point (" + thrownMessage + ") with no other diagnosable cause found"
                : "Ghidra's FunctionManager.createFunction returned null with no further detail "
                    + "from the API; entry point may not sit on a valid code unit boundary");
        }

        JsonObject err = errorResult("Failed to create function at " + addr.toString() + ": "
            + String.join("; ", reasons));
        err.add("detail", detail);
        return err;
    }

    private JsonObject handleDeleteFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        if (target == null || target.isEmpty()) {
            return errorResult("Function target required");
        }

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) {
                return errorResult(buildFunctionTargetHint(target));
            }

            Address entry = func.getEntryPoint();
            String name = func.getName();
            int txId = currentProgram.startTransaction("Delete function");
            try {
                fm.removeFunction(entry);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("address", entry.toString());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete function: " + e.getMessage());
        }
    }

    private JsonObject handleDecompile(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        Function func = fm.getFunctionContaining(addr);
        if (func == null) {
            return errorResult("No function at address " + addrStr);
        }

        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.openProgram(currentProgram);

            TaskMonitor mon = monitor;
            // Ghidra defines zero as no native decompiler timeout. Large but
            // valid functions can exceed the historical hard-coded 30 seconds,
            // so default to unbounded and let callers opt into a ceiling.
            int timeoutSecs = Math.max(0, getArgInt(args, "timeout_secs", 0));
            DecompileResults results = decompiler.decompileFunction(func, timeoutSecs, mon);

            if (results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();
                JsonObject result = new JsonObject();
                result.addProperty("name", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                String sig = null;
                try {
                    sig = func.getPrototypeString(false, false);
                } catch (Exception e) {
                    // ignore
                }
                if (sig != null) {
                    result.addProperty("signature", sig);
                } else {
                    result.add("signature", JsonNull.INSTANCE);
                }
                result.addProperty("code", code);

                boolean withVars = getArgBool(args, "with_vars", false);
                boolean withParams = getArgBool(args, "with_params", false);

                if (withVars || withParams) {
                    ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                    if (highFunc != null) {
                        ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();

                        if (withParams) {
                            JsonArray params = new JsonArray();
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                            while (symIter.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                                if (sym.isParameter()) {
                                    JsonObject paramObj = new JsonObject();
                                    paramObj.addProperty("name", sym.getName());
                                    paramObj.addProperty("type", sym.getDataType().getName());
                                    paramObj.addProperty("size", sym.getSize());
                                    paramObj.addProperty("storage", sym.getStorage().toString());
                                    params.add(paramObj);
                                }
                            }
                            result.add("params", params);
                        }

                        if (withVars) {
                            JsonArray vars = new JsonArray();
                            Iterator<ghidra.program.model.pcode.HighSymbol> symIter2 = lsm.getSymbols();
                            while (symIter2.hasNext()) {
                                ghidra.program.model.pcode.HighSymbol sym = symIter2.next();
                                if (!sym.isParameter()) {
                                    JsonObject varObj = new JsonObject();
                                    varObj.addProperty("name", sym.getName());
                                    varObj.addProperty("type", sym.getDataType().getName());
                                    varObj.addProperty("size", sym.getSize());
                                    varObj.addProperty("storage", sym.getStorage().toString());
                                    vars.add(varObj);
                                }
                            }
                            result.add("variables", vars);
                        }
                    }
                }

                return result;
            } else {
                String detail = results.getErrorMessage();
                if (detail == null || detail.trim().isEmpty()) {
                    detail = "no diagnostic returned by Ghidra";
                }
                String prefix;
                if (results.isTimedOut()) {
                    prefix = "Decompilation timed out" +
                        (timeoutSecs == 0 ? "" : " after " + timeoutSecs + " seconds");
                } else if (results.isCancelled()) {
                    prefix = "Decompilation cancelled";
                } else if (results.failedToStart()) {
                    prefix = "Decompiler failed to start";
                } else {
                    prefix = "Decompilation failed";
                }
                return errorResult(prefix + " for " + func.getName() + " at " +
                    func.getEntryPoint() + ": " + detail.trim());
            }
        } finally {
            decompiler.dispose();
        }
    }

    private JsonObject handleListStrings(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        JsonArray strings = new JsonArray();
        Listing listing = currentProgram.getListing();
        DataIterator dataIter = listing.getDefinedData(true);
        int count = 0;

        while (dataIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Data data = dataIter.next();
            if (data.hasStringValue()) {
                try {
                    String val = data.getValue().toString();

                    if (nameFilter != null && !val.toLowerCase().contains(nameFilter.toLowerCase())) {
                        continue;
                    }

                    JsonObject strData = new JsonObject();
                    strData.addProperty("address", data.getAddress().toString());
                    strData.addProperty("value", val);
                    strData.addProperty("length", val.length());
                    strings.add(strData);
                    count++;
                } catch (Exception e) {
                    // skip
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("strings", strings);
        result.addProperty("count", strings.size());
        return result;
    }

    private JsonObject handleListImports() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonArray imports = new JsonArray();
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        ExternalManager extMgr = currentProgram.getExternalManager();

        SymbolIterator extSymbols = symbolTable.getExternalSymbols();
        while (extSymbols.hasNext()) {
            Symbol symbol = extSymbols.next();
            ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
            if (extLoc != null) {
                JsonObject importData = new JsonObject();
                importData.addProperty("name", symbol.getName());
                importData.addProperty("address", symbol.getAddress().toString());
                importData.addProperty("library", extLoc.getLibraryName());
                imports.add(importData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("imports", imports);
        result.addProperty("count", imports.size());
        return result;
    }

    private JsonObject handleListExports() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonArray exports = new JsonArray();
        SymbolTable symbolTable = currentProgram.getSymbolTable();

        SymbolIterator symIter = symbolTable.getSymbolIterator();
        while (symIter.hasNext()) {
            Symbol symbol = symIter.next();
            if (symbol.isExternalEntryPoint()) {
                JsonObject exportData = new JsonObject();
                exportData.addProperty("name", symbol.getName());
                exportData.addProperty("address", symbol.getAddress().toString());
                exports.add(exportData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("exports", exports);
        result.addProperty("count", exports.size());
        return result;
    }

    private JsonObject handleMemoryMap() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        JsonArray blocks = new JsonArray();
        Memory memory = currentProgram.getMemory();

        for (MemoryBlock block : memory.getBlocks()) {
            StringBuilder perms = new StringBuilder();
            if (block.isRead()) perms.append("r");
            if (block.isWrite()) perms.append("w");
            if (block.isExecute()) perms.append("x");

            JsonObject blockData = new JsonObject();
            blockData.addProperty("name", block.getName());
            blockData.addProperty("start", block.getStart().toString());
            blockData.addProperty("end", block.getEnd().toString());
            blockData.addProperty("size", block.getSize());
            blockData.addProperty("permissions", perms.toString());
            blockData.addProperty("is_initialized", block.isInitialized());
            blockData.addProperty("is_loaded", block.isLoaded());
            blocks.add(blockData);
        }

        JsonObject result = new JsonObject();
        result.add("blocks", blocks);
        result.addProperty("count", blocks.size());
        return result;
    }

    private JsonObject handleXrefsTo(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        for (Reference ref : refMgr.getReferencesTo(addr)) {
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = fm.getFunctionContaining(fromAddr);
            Function toFunc = fm.getFunctionContaining(addr);

            JsonObject xrefData = new JsonObject();
            xrefData.addProperty("from", fromAddr.toString());
            xrefData.addProperty("to", addr.toString());
            xrefData.addProperty("ref_type", ref.getReferenceType().toString());
            if (fromFunc != null) {
                xrefData.addProperty("from_function", fromFunc.getName());
            } else {
                xrefData.add("from_function", JsonNull.INSTANCE);
            }
            if (toFunc != null) {
                xrefData.addProperty("to_function", toFunc.getName());
            } else {
                xrefData.add("to_function", JsonNull.INSTANCE);
            }
            xrefs.add(xrefData);
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleXrefsFrom(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        // If address is a function entry point, scan the entire function body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry point — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleXrefsList(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String addrStr = getArgString(args, "address");
        if (addrStr == null || addrStr.isEmpty()) {
            return errorResult("No address provided");
        }

        Address addr = resolveAddress(addrStr);
        if (addr == null) {
            return errorResult(buildFunctionTargetHint(addrStr));
        }

        JsonArray xrefs = new JsonArray();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();

        // References TO the target address
        for (Reference ref : refMgr.getReferencesTo(addr)) {
            Address fromAddr = ref.getFromAddress();
            Function fromFunc = fm.getFunctionContaining(fromAddr);
            Function toFunc = fm.getFunctionContaining(addr);

            JsonObject xrefData = new JsonObject();
            xrefData.addProperty("from", fromAddr.toString());
            xrefData.addProperty("to", addr.toString());
            xrefData.addProperty("ref_type", ref.getReferenceType().toString());
            xrefData.addProperty("direction", "to");
            if (fromFunc != null) {
                xrefData.addProperty("from_function", fromFunc.getName());
            } else {
                xrefData.add("from_function", JsonNull.INSTANCE);
            }
            if (toFunc != null) {
                xrefData.addProperty("to_function", toFunc.getName());
            } else {
                xrefData.add("to_function", JsonNull.INSTANCE);
            }
            xrefs.add(xrefData);
        }

        // References FROM the target — if it's a function, scan the entire body
        Function func = fm.getFunctionAt(addr);
        if (func != null) {
            ghidra.program.model.address.AddressSetView body = func.getBody();
            ghidra.program.model.address.AddressIterator addrIter = body.getAddresses(true);
            while (addrIter.hasNext()) {
                Address instrAddr = addrIter.next();
                Reference[] refs = refMgr.getReferencesFrom(instrAddr);
                for (Reference ref : refs) {
                    Address toAddr = ref.getToAddress();
                    Function toFunc = fm.getFunctionContaining(toAddr);

                    JsonObject xrefData = new JsonObject();
                    xrefData.addProperty("from", instrAddr.toString());
                    xrefData.addProperty("to", toAddr.toString());
                    xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                    xrefData.addProperty("direction", "from");
                    xrefData.addProperty("from_function", func.getName());
                    if (toFunc != null) {
                        xrefData.addProperty("to_function", toFunc.getName());
                    } else {
                        xrefData.add("to_function", JsonNull.INSTANCE);
                    }
                    xrefs.add(xrefData);
                }
            }
        } else {
            // Not a function entry — just get refs from this single address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                Address toAddr = ref.getToAddress();
                Function fromFunc = fm.getFunctionContaining(addr);
                Function toFunc = fm.getFunctionContaining(toAddr);

                JsonObject xrefData = new JsonObject();
                xrefData.addProperty("from", addr.toString());
                xrefData.addProperty("to", toAddr.toString());
                xrefData.addProperty("ref_type", ref.getReferenceType().toString());
                xrefData.addProperty("direction", "from");
                if (fromFunc != null) {
                    xrefData.addProperty("from_function", fromFunc.getName());
                } else {
                    xrefData.add("from_function", JsonNull.INSTANCE);
                }
                if (toFunc != null) {
                    xrefData.addProperty("to_function", toFunc.getName());
                } else {
                    xrefData.add("to_function", JsonNull.INSTANCE);
                }
                xrefs.add(xrefData);
            }
        }

        JsonObject result = new JsonObject();
        result.add("xrefs", xrefs);
        result.addProperty("count", xrefs.size());
        return result;
    }

    private JsonObject handleImport(JsonObject args) {
        String binaryPath = getArgString(args, "binary_path");
        if (binaryPath == null || binaryPath.isEmpty()) {
            return errorResult("No binary_path provided");
        }

        String programName = getArgString(args, "program");
        File binaryFile = new File(binaryPath);
        if (programName == null || programName.isEmpty()) {
            programName = binaryFile.getName();
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        if (!binaryFile.exists()) {
            return errorResult("Binary file not found: " + binaryPath);
        }

        try {
            TaskMonitor mon = monitor;
            MessageLog log = new MessageLog();
            Object consumer = project;

            // Ghidra 12+ API: importByUsingBestGuess(File, Project, String, Object, MessageLog, TaskMonitor)
            Object loadResults = AutoImporter.importByUsingBestGuess(
                binaryFile, project, "/", consumer, log, mon
            );

            if (loadResults == null) {
                return errorResult("Failed to import binary");
            }

            // Save and release - loadResults is a LoadResults<Program>
            // Use reflection to handle API differences across Ghidra versions
            try {
                java.lang.reflect.Method saveMethod = loadResults.getClass().getMethod("save", TaskMonitor.class);
                // Actually it's per-loaded item; iterate
                // LoadResults implements Iterable<Loaded<DomainObject>>
                if (loadResults instanceof Iterable) {
                    for (Object loaded : (Iterable<?>) loadResults) {
                        java.lang.reflect.Method saveMeth = loaded.getClass().getMethod("save", TaskMonitor.class);
                        saveMeth.invoke(loaded, mon);
                    }
                }
                java.lang.reflect.Method releaseMethod = loadResults.getClass().getMethod("release", Object.class);
                releaseMethod.invoke(loadResults, consumer);
            } catch (Exception reflectEx) {
                // Fallback: try direct cast for older APIs
                printerr("Import save warning: " + reflectEx.getMessage());
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Import failed: " + e.getMessage());
        }
    }

    private JsonObject handleAnalyze(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            if (currentProgram == null) {
                return errorResult("No program loaded. Use 'open_program' or 'import' first.");
            }
            programName = currentProgram.getName();
        }

        if (currentProgram == null) {
            return errorResult("No program currently loaded");
        }

        // If requested program differs from current, switch to it
        if (!currentProgram.getName().equals(programName)) {
            JsonObject switchArgs = new JsonObject();
            switchArgs.addProperty("program", programName);
            JsonObject switchResult = handleOpenProgram(switchArgs);
            if (switchResult.has("error")) {
                return switchResult;
            }
        }

        try {
            TaskMonitor mon = monitor;

            // Use GhidraScript's built-in analyzeAll which works across Ghidra versions
            analyzeAll(currentProgram);

            // Save the analyzed program. The bridge opens the program in
            // `-process` mode against a project created by a clean one-shot
            // import, so the program is writable and this save is durable.
            try {
                currentProgram.save("Analysis complete", mon);
            } catch (Exception saveErr) {
                // Best effort - durable persistence also happens on clean shutdown.
            }

            FunctionManager fm = currentProgram.getFunctionManager();
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            result.addProperty("function_count", fm.getFunctionCount());
            return result;

        } catch (Exception e) {
            return errorResult("Analysis failed: " + e.getMessage());
        }
    }

    private JsonObject handleListPrograms() {
        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();
            JsonArray programs = new JsonArray();

            for (DomainFile domainFile : rootFolder.getFiles()) {
                boolean isCurrent = (currentProgram != null &&
                    domainFile.getName().equals(currentProgram.getName()));

                JsonObject prog = new JsonObject();
                prog.addProperty("name", domainFile.getName());
                prog.addProperty("path", domainFile.getPathname());
                prog.addProperty("type", domainFile.getContentType());
                prog.addProperty("version", domainFile.getVersion());
                prog.addProperty("current", isCurrent);

                // Add analysis metadata
                if (isCurrent && currentProgram != null) {
                    // For current program, use live data
                    FunctionManager fm = currentProgram.getFunctionManager();
                    int funcCount = fm.getFunctionCount();
                    prog.addProperty("function_count", funcCount);
                    prog.addProperty("analyzed", funcCount > 1);
                    prog.addProperty("executable_format", currentProgram.getExecutableFormat());
                } else {
                    // For other programs, use DomainFile metadata
                    try {
                        java.util.Map<String, String> metadata = domainFile.getMetadata();
                        if (metadata != null) {
                            String funcCountStr = metadata.get("# of Functions");
                            int funcCount = 0;
                            if (funcCountStr != null) {
                                try { funcCount = Integer.parseInt(funcCountStr.trim()); }
                                catch (NumberFormatException ignored) {}
                            }
                            prog.addProperty("function_count", funcCount);
                            prog.addProperty("analyzed", funcCount > 1);
                            String exeFmt = metadata.get("Executable Format");
                            if (exeFmt != null) {
                                prog.addProperty("executable_format", exeFmt);
                            }
                        }
                    } catch (Exception ignored) {
                        // metadata not available for this file
                    }
                }

                programs.add(prog);
            }

            JsonObject result = new JsonObject();
            result.add("programs", programs);
            result.addProperty("count", programs.size());
            result.addProperty("has_current_program", currentProgram != null);
            if (currentProgram != null) {
                result.addProperty("current_program_name", currentProgram.getName());
            }
            return result;

        } catch (Exception e) {
            return errorResult("Failed to list programs: " + e.getMessage());
        }
    }

    private JsonObject handleOpenProgram(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        // Already the current program? No-op.
        if (currentProgram != null && currentProgram.getName().equals(programName)) {
            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", programName);
            return result;
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            DomainFolder rootFolder = projectData.getRootFolder();

            // Find the domain file by name
            DomainFile domainFile = null;
            for (DomainFile f : rootFolder.getFiles()) {
                if (f.getName().equals(programName)) {
                    domainFile = f;
                    break;
                }
            }

            if (domainFile == null) {
                // Try as a path
                String path = programName.startsWith("/") ? programName : "/" + programName;
                domainFile = projectData.getFile(path);
            }

            if (domainFile == null) {
                // Build list of available programs for error message
                StringBuilder available = new StringBuilder();
                for (DomainFile f : rootFolder.getFiles()) {
                    if (available.length() > 0) available.append(", ");
                    available.append(f.getName());
                }
                return errorResult("Program not found: " + programName +
                    ". Available: " + available.toString());
            }

            Object consumer = project;
            TaskMonitor mon = monitor;

            // Release current program if one is open
            if (currentProgram != null) {
                try {
                    currentProgram.save("Auto-save before switch", mon);
                } catch (Exception e) {
                    // Best effort save
                }
                try {
                    currentProgram.release(consumer);
                } catch (Exception e) {
                    // Best effort release
                }
            }

            // Open the requested program
            DomainObject domObj = domainFile.getDomainObject(consumer, true, false, mon);
            if (domObj instanceof ghidra.program.model.listing.Program) {
                currentProgram = (ghidra.program.model.listing.Program) domObj;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "success");
            result.addProperty("program", currentProgram.getName());
            return result;

        } catch (Exception e) {
            return errorResult("Failed to open program: " + e.getMessage());
        }
    }

    private JsonObject handleProgramClose() {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String programName = currentProgram.getName();

        // No save attempt here: currentProgram.save() always fails with
        // "Unable to lock due to active transaction" while this postScript is
        // running (see the comment in run()'s finally block) -- confirmed
        // empirically, including with zero pending edits, so it is not a race
        // to work around, it is a hard constraint of the execution model.
        // Pending changes remain in memory and are only flushed to disk when
        // the bridge process itself exits; use `ghidra program save` (stops
        // and restarts the bridge) or `ghidra stop` to persist them.

        // In headless mode, we release the program
        try {
            Project project = state.getProject();
            if (project != null) {
                currentProgram.release(project);
            }
        } catch (Exception e) {
            // Best effort
        }

        currentProgram = null;

        JsonObject result = new JsonObject();
        result.addProperty("status", "closed");
        result.addProperty("program", programName);
        result.addProperty("note", "not saved to disk -- run `ghidra program save` or `ghidra stop` to persist pending changes");
        return result;
    }

    private JsonObject handleProgramDelete(JsonObject args) {
        String programName = getArgString(args, "program");
        if (programName == null || programName.isEmpty()) {
            return errorResult("Program name required");
        }

        Project project = state.getProject();
        if (project == null) {
            return errorResult("No project open");
        }

        try {
            ProjectData projectData = project.getProjectData();
            String path = programName.startsWith("/") ? programName : "/" + programName;
            DomainFile programFile = projectData.getFile(path);

            if (programFile == null) {
                return errorResult("Program not found: " + programName);
            }

            programFile.delete();

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("program", programName);
            return result;

        } catch (Exception e) {
            return errorResult("Failed to delete program: " + e.getMessage());
        }
    }

    private JsonObject handleProgramExport(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        String exportFormat = getArgString(args, "format");
        if (exportFormat == null) exportFormat = "json";
        String outputPath = getArgString(args, "output");

        if ("json".equals(exportFormat)) {
            // Get program info as base
            JsonObject data = handleProgramInfo();
            if (data.has("error")) {
                return data;
            }

            // Add function list
            FunctionManager fm = currentProgram.getFunctionManager();
            JsonArray functions = new JsonArray();
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                JsonObject funcObj = new JsonObject();
                funcObj.addProperty("name", func.getName());
                funcObj.addProperty("address", func.getEntryPoint().toString());
                funcObj.addProperty("size", func.getBody().getNumAddresses());
                functions.add(funcObj);
            }
            data.add("functions", functions);

            if (outputPath != null && !outputPath.isEmpty()) {
                try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
                    Gson prettyGson = new GsonBuilder().setPrettyPrinting().create();
                    pw.println(prettyGson.toJson(data));

                    JsonObject result = new JsonObject();
                    result.addProperty("status", "exported");
                    result.addProperty("format", "json");
                    result.addProperty("output", outputPath);
                    return result;
                } catch (IOException e) {
                    return errorResult("Failed to write file: " + e.getMessage());
                }
            } else {
                return data;
            }
        } else {
            // Generic path: dispatch to a built-in Ghidra Exporter resolved by name.
            // Resolving via the exporter registry (rather than a hardcoded class +
            // signature) keeps this working across Ghidra versions.
            if (outputPath == null || outputPath.isEmpty()) {
                return errorResult("Output path required for format: " + exportFormat);
            }
            try {
                // Map short format codes to the concrete Ghidra Exporter classes.
                // Instantiating the class directly avoids depending on a registry
                // lookup API whose name has changed across Ghidra versions.
                java.util.Map<String, String> classMap = new java.util.HashMap<>();
                classMap.put("xml", "ghidra.app.util.exporter.XmlExporter");
                classMap.put("c", "ghidra.app.util.exporter.CppExporter");
                classMap.put("cpp", "ghidra.app.util.exporter.CppExporter");
                classMap.put("binary", "ghidra.app.util.exporter.BinaryExporter");
                classMap.put("bin", "ghidra.app.util.exporter.BinaryExporter");
                classMap.put("gzf", "ghidra.app.util.exporter.GzfExporter");
                classMap.put("asm", "ghidra.app.util.exporter.AsciiExporter");
                classMap.put("ascii", "ghidra.app.util.exporter.AsciiExporter");
                classMap.put("hex", "ghidra.app.util.exporter.IntelHexExporter");
                classMap.put("html", "ghidra.app.util.exporter.HtmlExporter");

                String className = classMap.get(exportFormat.toLowerCase());
                if (className == null) {
                    return errorResult("Unsupported export format: " + exportFormat
                        + " (supported: json, xml, c, binary, gzf, ascii/asm, hex, html)");
                }

                Class<?> exporterClass = Class.forName(className);
                Object exporter = exporterClass.getDeclaredConstructor().newInstance();

                // Resolve export(File, DomainObject, AddressSetView, TaskMonitor) by
                // name + arity to tolerate signature drift across Ghidra versions.
                java.lang.reflect.Method exportMethod = null;
                for (java.lang.reflect.Method m : exporterClass.getMethods()) {
                    if (m.getName().equals("export") && m.getParameterCount() == 4) {
                        exportMethod = m;
                        break;
                    }
                }
                if (exportMethod == null) {
                    return errorResult("Exporter has no 4-arg export method: " + exportFormat);
                }

                TaskMonitor mon = monitor;
                exportMethod.invoke(exporter, new File(outputPath), currentProgram, null, mon);

                JsonObject result = new JsonObject();
                result.addProperty("status", "exported");
                result.addProperty("format", exportFormat);
                result.addProperty("output", outputPath);
                return result;
            } catch (Exception e) {
                return errorResult("Failed to export (" + exportFormat + "): " + e.getMessage());
            }
        }
    }

    // ================================================================
    // M2: Extended Command Handlers
    // ================================================================

    // --- Find Handlers ---

    private JsonObject handleFindString(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            JsonArray results = new JsonArray();

            // Phase 1: Search pre-analyzed string data types from the listing.
            // This is fast and returns strings Ghidra's analyzer has already classified.
            Listing listing = currentProgram.getListing();
            DataIterator dataIter = listing.getDefinedData(true);

            while (dataIter.hasNext()) {
                Data data = dataIter.next();
                if (data.hasStringValue()) {
                    try {
                        String val = data.getValue().toString();
                        if (pattern.isEmpty() || val.toLowerCase().contains(pattern.toLowerCase())) {
                            JsonObject item = new JsonObject();
                            item.addProperty("address", data.getAddress().toString());
                            item.addProperty("value", val);
                            item.addProperty("length", data.getLength());
                            results.add(item);
                        }
                    } catch (Exception e) { /* skip */ }
                }
            }

            // Phase 2: If listing search found nothing and we have a pattern,
            // fall back to raw memory scanning. This catches strings that Ghidra's
            // analyzer didn't classify as string data types (common on PE binaries,
            // and on macOS arm64 Rust binaries where literals stay undefined).
            //
            // This is a heuristic: it walks back to the start of the surrounding
            // printable run and reads forward, capped at MEM_SCAN_MAX_LEN. Strings
            // without a NUL/non-printable separator (e.g. packed Rust &str literals)
            // can't have their exact boundaries recovered from raw bytes alone, so
            // these results are marked with "source":"memory-scan".
            if (results.size() == 0 && !pattern.isEmpty()) {
                final int MEM_SCAN_MAX_LEN = 256;
                Memory memory = currentProgram.getMemory();
                byte[] searchBytes = pattern.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                Address addr = memory.getMinAddress();
                while (addr != null && results.size() < 100) {
                    Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                    if (found == null) break;

                    // Walk back to the start of the printable run so the result
                    // isn't truncated to the match offset (e.g. losing "Hello, ").
                    Address start = backScanToStringStart(memory, found, MEM_SCAN_MAX_LEN);
                    String extracted = extractStringAt(memory, start, MEM_SCAN_MAX_LEN);
                    if (extracted != null && !extracted.isEmpty()) {
                        JsonObject item = new JsonObject();
                        item.addProperty("address", start.toString());
                        item.addProperty("value", extracted);
                        item.addProperty("length", extracted.length());
                        item.addProperty("source", "memory-scan");
                        results.add(item);
                    }

                    // Advance past this match (use the matched pattern length so we
                    // don't loop forever if extraction came back empty).
                    addr = found.add(Math.max(1, searchBytes.length));
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find strings: " + e.getMessage());
        }
    }

    /**
     * Walk backward from a match address to the start of the surrounding
     * printable-ASCII run (stopping at a null/non-printable byte, the memory
     * block start, or after maxBack bytes). Returns the start address.
     *
     * For NUL-terminated strings this recovers the true start. For packed
     * non-terminated strings (Rust &str literals) there is no separator, so
     * the run may include preceding literals — bounded by maxBack.
     */
    private Address backScanToStringStart(Memory memory, Address matchAddr, int maxBack) {
        Address start = matchAddr;
        try {
            for (int i = 0; i < maxBack; i++) {
                Address prev = start.subtract(1);
                if (prev == null || !memory.contains(prev)) break;
                byte b = memory.getByte(prev);
                if (b == 0 || b < 0x20 || b > 0x7e) break;
                start = prev;
            }
        } catch (Exception e) {
            // Hit a block boundary or unreadable byte; current start is fine.
        }
        return start;
    }

    /**
     * Extract a printable string starting at the given address.
     * Reads until a null byte, non-printable character, or maxLen is reached.
     */
    private String extractStringAt(Memory memory, Address addr, int maxLen) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < maxLen; i++) {
                byte b = memory.getByte(addr.add(i));
                if (b == 0) break;
                if (b < 0x20 || b > 0x7e) break; // non-printable ASCII
                sb.append((char) b);
            }
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    private JsonObject handleFindBytes(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String hexPattern = getArgString(args, "hex");
        if (hexPattern == null || hexPattern.isEmpty()) {
            return errorResult("No hex pattern provided");
        }

        try {
            String hexClean = hexPattern.replace("0x", "").replace(" ", "");
            byte[] searchBytes = new byte[hexClean.length() / 2];
            for (int i = 0; i < searchBytes.length; i++) {
                searchBytes[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = currentProgram.getMemory();
            JsonArray results = new JsonArray();

            Address addr = memory.getMinAddress();
            while (addr != null && results.size() < 100) {
                Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                if (found == null) break;
                JsonObject item = new JsonObject();
                item.addProperty("address", found.toString());
                results.add(item);
                addr = found.add(1);
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find bytes: " + e.getMessage());
        }
    }

    private JsonObject handleFindFunction(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String pattern = getArgString(args, "pattern");
        if (pattern == null) pattern = "";

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            JsonArray results = new JsonArray();
            boolean isWildcard = pattern.contains("*");

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String name = func.getName();
                boolean matches;

                if (isWildcard) {
                    // Simple wildcard matching: convert * to regex .*
                    String regex = pattern.replace(".", "\\.").replace("*", ".*");
                    matches = name.matches(regex);
                } else {
                    matches = name.toLowerCase().contains(pattern.toLowerCase());
                }

                if (matches) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", name);
                    item.addProperty("address", func.getEntryPoint().toString());
                    item.addProperty("size", func.getBody().getNumAddresses());
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find functions: " + e.getMessage());
        }
    }

    private JsonObject handleFindCalls(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String functionTarget = getArgString(args, "function");
        if (functionTarget == null || functionTarget.isEmpty()) {
            return errorResult("No function target provided");
        }

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            Function targetFunc = findFunctionByNameOrAddress(functionTarget);

            if (targetFunc == null) {
                return errorResult(buildFunctionTargetHint(functionTarget));
            }

            ReferenceManager refMgr = currentProgram.getReferenceManager();
            Address targetAddr = targetFunc.getEntryPoint();
            JsonArray results = new JsonArray();

            for (Reference ref : refMgr.getReferencesTo(targetAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Address fromAddr = ref.getFromAddress();
                    Function callerFunc = fm.getFunctionContaining(fromAddr);
                    JsonObject item = new JsonObject();
                    item.addProperty("address", fromAddr.toString());
                    item.addProperty("caller", callerFunc != null ? callerFunc.getName() : "unknown");
                    item.addProperty("type", ref.getReferenceType().toString());
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            result.addProperty("target", functionTarget);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find calls: " + e.getMessage());
        }
    }

    private JsonObject handleFindCrypto() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            Memory memory = currentProgram.getMemory();
            JsonArray results = new JsonArray();

            String[][] cryptoPatterns = {
                {"AES S-box", "637c777bf26b6fc53001672bfed7ab76"},
                {"SHA-256", "428a2f98d728ae227137449123ef65cd"},
                {"MD5", "d76aa478e8c7b756242070db01234567"}
            };

            for (String[] cp : cryptoPatterns) {
                String name = cp[0];
                String hexPattern = cp[1];
                byte[] searchBytes = new byte[hexPattern.length() / 2];
                for (int i = 0; i < searchBytes.length; i++) {
                    searchBytes[i] = (byte) Integer.parseInt(hexPattern.substring(i * 2, i * 2 + 2), 16);
                }

                Address addr = memory.getMinAddress();
                Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                if (found != null) {
                    JsonObject item = new JsonObject();
                    item.addProperty("type", name);
                    item.addProperty("address", found.toString());
                    item.addProperty("pattern", hexPattern);
                    results.add(item);
                }
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find crypto: " + e.getMessage());
        }
    }

    private JsonObject handleFindInteresting() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            ReferenceManager refMgr = currentProgram.getReferenceManager();
            List<JsonObject> resultsList = new ArrayList<>();

            String[] suspiciousNames = {"password", "key", "encrypt", "decrypt", "crypt",
                "auth", "login", "admin", "secret"};

            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext()) {
                Function func = iter.next();
                String funcName = func.getName();
                Address funcAddr = func.getEntryPoint();
                long funcSize = func.getBody().getNumAddresses();

                int xrefCount = 0;
                for (Reference ref : refMgr.getReferencesTo(funcAddr)) {
                    xrefCount++;
                }

                JsonArray reasons = new JsonArray();

                if (funcSize > 1000) {
                    reasons.add(new JsonPrimitive("large function (" + funcSize + " bytes)"));
                }
                if (xrefCount > 50) {
                    reasons.add(new JsonPrimitive("many xrefs (" + xrefCount + ")"));
                }
                for (String sus : suspiciousNames) {
                    if (funcName.toLowerCase().contains(sus)) {
                        reasons.add(new JsonPrimitive("suspicious name"));
                        break;
                    }
                }

                if (reasons.size() > 0) {
                    JsonObject item = new JsonObject();
                    item.addProperty("name", funcName);
                    item.addProperty("address", funcAddr.toString());
                    item.addProperty("size", funcSize);
                    item.addProperty("xrefs", xrefCount);
                    item.add("reasons", reasons);
                    resultsList.add(item);
                }
            }

            // Sort by number of reasons (descending)
            resultsList.sort((a, b) -> b.getAsJsonArray("reasons").size() - a.getAsJsonArray("reasons").size());

            JsonArray results = new JsonArray();
            int limit = Math.min(50, resultsList.size());
            for (int i = 0; i < limit; i++) {
                results.add(resultsList.get(i));
            }

            JsonObject result = new JsonObject();
            result.add("results", results);
            result.addProperty("count", resultsList.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to find interesting functions: " + e.getMessage());
        }
    }

    // --- Symbol Handlers ---

    private JsonObject handleSymbolList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        SymbolTable symbolTable = currentProgram.getSymbolTable();
        JsonArray symbols = new JsonArray();
        int count = 0;

        SymbolIterator symIter = symbolTable.getAllSymbols(true);
        while (symIter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Symbol symbol = symIter.next();
            String name = symbol.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject symData = new JsonObject();
            symData.addProperty("name", name);
            symData.addProperty("address", symbol.getAddress().toString());
            symData.addProperty("type", symbol.getSymbolType().toString());
            symData.addProperty("source", symbol.getSource().toString());
            symData.addProperty("is_primary", symbol.isPrimary());
            symbols.add(symData);
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("symbols", symbols);
        result.addProperty("count", symbols.size());
        return result;
    }

    private JsonObject handleSymbolGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressOrName = getArgString(args, "name");
        if (addressOrName == null || addressOrName.isEmpty()) {
            return errorResult("No symbol name or address provided");
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Try as address first
        boolean looksLikeAddress = addressOrName.startsWith("0x") ||
            addressOrName.chars().allMatch(c -> "0123456789abcdefABCDEF".indexOf(c) >= 0);

        if (looksLikeAddress) {
            try {
                Address addr = currentProgram.getAddressFactory().getAddress(addressOrName);
                if (addr != null) {
                    Symbol[] symbolsAtAddr = symbolTable.getSymbols(addr);
                    if (symbolsAtAddr.length == 0) {
                        return errorResult("No symbol at address: " + addressOrName);
                    }
                    JsonArray syms = new JsonArray();
                    for (Symbol s : symbolsAtAddr) {
                        JsonObject symData = new JsonObject();
                        symData.addProperty("name", s.getName());
                        symData.addProperty("address", s.getAddress().toString());
                        symData.addProperty("type", s.getSymbolType().toString());
                        symData.addProperty("source", s.getSource().toString());
                        syms.add(symData);
                    }
                    JsonObject result = new JsonObject();
                    result.add("symbols", syms);
                    return result;
                }
            } catch (Exception e) {
                // fall through to name lookup
            }
        }

        // Try as name
        SymbolIterator symsByName = symbolTable.getSymbols(addressOrName);
        JsonArray syms = new JsonArray();
        while (symsByName.hasNext()) {
            Symbol s = symsByName.next();
            JsonObject symData = new JsonObject();
            symData.addProperty("name", s.getName());
            symData.addProperty("address", s.getAddress().toString());
            symData.addProperty("type", s.getSymbolType().toString());
            symData.addProperty("source", s.getSource().toString());
            syms.add(symData);
        }

        if (syms.size() == 0) {
            return errorResult("Symbol not found: " + addressOrName);
        }

        JsonObject result = new JsonObject();
        result.add("symbols", syms);
        return result;
    }

    private JsonObject handleSymbolCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String name = getArgString(args, "name");
        if (addressStr == null || name == null) {
            return errorResult("Address and name required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            int txId = currentProgram.startTransaction("Create symbol");
            try {
                SymbolTable symbolTable = currentProgram.getSymbolTable();
                symbolTable.createLabel(addr, name, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("address", addressStr);
            result.addProperty("name", name);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create symbol: " + e.getMessage());
        }
    }

    /** Strip an optional 0x/0X prefix and lowercase, for tolerant address comparison. */
    private String normalizeAddressForCompare(String addr) {
        if (addr == null) return null;
        String a = addr.trim().toLowerCase();
        if (a.startsWith("0x")) a = a.substring(2);
        return a;
    }

    /**
     * Resolve exactly which symbols named `name` a mutation should touch.
     *
     * Ghidra auto-generates names (`caseD_XX`, `LAB_XXXX`, ...) that are
     * routinely reused across unrelated addresses program-wide, so a bare
     * name is not a safe mutation target on its own: without this guard,
     * `symbol rename`/`symbol delete` would silently touch every symbol
     * sharing that name, not just the one address the caller meant.
     *
     * When `addresses` is non-empty, scope to exactly those addresses
     * (erroring if any requested address has no matching symbol). When it's
     * empty and more than one symbol shares `name`, refuse to guess.
     */
    private List<Symbol> resolveScopedSymbols(SymbolTable symbolTable, String name, String[] addresses)
            throws Exception {
        SymbolIterator syms = symbolTable.getSymbols(name);
        List<Symbol> all = new ArrayList<>();
        while (syms.hasNext()) {
            all.add(syms.next());
        }
        if (all.isEmpty()) {
            throw new IllegalArgumentException("Symbol not found: " + name);
        }

        if (addresses != null && addresses.length > 0) {
            Set<String> wanted = new HashSet<>();
            for (String a : addresses) wanted.add(normalizeAddressForCompare(a));
            List<Symbol> scoped = new ArrayList<>();
            for (Symbol s : all) {
                if (wanted.contains(normalizeAddressForCompare(s.getAddress().toString()))) {
                    scoped.add(s);
                }
            }
            if (scoped.isEmpty()) {
                throw new IllegalArgumentException(
                    "No symbol named '" + name + "' at the given address(es)");
            }
            return scoped;
        }

        if (all.size() > 1) {
            StringBuilder addrs = new StringBuilder();
            for (Symbol s : all) {
                if (addrs.length() > 0) addrs.append(", ");
                addrs.append(s.getAddress().toString());
            }
            throw new IllegalArgumentException("'" + name + "' matches " + all.size()
                + " symbols at addresses [" + addrs + "] -- pass explicit address(es) to pick "
                + "one, or request all of them explicitly");
        }

        return all;
    }

    private JsonObject handleSymbolDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String name = getArgString(args, "name");
        if (name == null) return errorResult("Symbol name required");
        String[] addresses = getArgStringArray(args, "addresses");

        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            List<Symbol> toDelete = resolveScopedSymbols(symbolTable, name, addresses);

            int txId = currentProgram.startTransaction("Delete symbol");
            try {
                for (Symbol s : toDelete) {
                    s.delete();
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("count", toDelete.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete symbol: " + e.getMessage());
        }
    }

    private JsonObject handleSymbolRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || newName == null) {
            return errorResult("old_name and new_name required");
        }
        String[] addresses = getArgStringArray(args, "addresses");

        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            List<Symbol> toRename = resolveScopedSymbols(symbolTable, oldName, addresses);

            JsonArray renamed = new JsonArray();
            int txId = currentProgram.startTransaction("Rename symbol");
            try {
                for (Symbol s : toRename) {
                    JsonObject entry = new JsonObject();
                    entry.addProperty("address", s.getAddress().toString());
                    s.setName(newName, SourceType.USER_DEFINED);
                    renamed.add(entry);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.add("addresses", renamed);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename symbol: " + e.getMessage());
        }
    }

    // --- Type Handlers ---

    private JsonObject handleTypeList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        JsonArray types = new JsonArray();

        Iterator<DataType> dtIter = dtm.getAllDataTypes();
        int count = 0;
        while (dtIter.hasNext()) {
            DataType dt = dtIter.next();
            if (limit > 0 && count >= limit) break;

            if (nameFilter != null && !dt.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject typeData = new JsonObject();
            typeData.addProperty("name", dt.getName());
            typeData.addProperty("path", dt.getPathName());
            typeData.addProperty("category", dt.getCategoryPath().toString());
            typeData.addProperty("size", dt.getLength());
            String kind;
            if (dt instanceof Structure) kind = "struct";
            else if (dt instanceof Union) kind = "union";
            else if (dt instanceof ghidra.program.model.data.Enum) kind = "enum";
            else if (dt instanceof TypeDef) kind = "typedef";
            else if (dt instanceof FunctionDefinition) kind = "functiondef";
            else if (dt instanceof Pointer) kind = "pointer";
            else if (dt instanceof Array) kind = "array";
            else kind = "other";
            typeData.addProperty("kind", kind);
            types.add(typeData);
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("types", types);
        result.addProperty("count", types.size());
        return result;
    }

    private JsonObject handleTypeGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        DataType dataType = resolveDataType(typeName);
        if (dataType == null) {
            return errorResult("Type not found: " + typeName);
        }

        JsonObject typeInfo = new JsonObject();
        typeInfo.addProperty("name", dataType.getName());
        typeInfo.addProperty("path", dataType.getPathName());
        typeInfo.addProperty("category", dataType.getCategoryPath().toString());
        typeInfo.addProperty("size", dataType.getLength());
        typeInfo.addProperty("description", dataType.getDescription());

        if (dataType instanceof Structure) {
            typeInfo.addProperty("kind", "struct");
            Structure struct = (Structure) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : struct.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof Union) {
            typeInfo.addProperty("kind", "union");
            Union union = (Union) dataType;
            JsonArray components = new JsonArray();
            for (DataTypeComponent comp : union.getComponents()) {
                JsonObject compObj = new JsonObject();
                compObj.addProperty("name", comp.getFieldName());
                compObj.addProperty("type", comp.getDataType().getName());
                compObj.addProperty("offset", comp.getOffset());
                compObj.addProperty("size", comp.getLength());
                components.add(compObj);
            }
            typeInfo.add("components", components);
        } else if (dataType instanceof ghidra.program.model.data.Enum) {
            typeInfo.addProperty("kind", "enum");
            ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
            JsonArray members = new JsonArray();
            for (String name : enumType.getNames()) {
                JsonObject member = new JsonObject();
                member.addProperty("name", name);
                member.addProperty("value", enumType.getValue(name));
                members.add(member);
            }
            typeInfo.add("members", members);
        } else if (dataType instanceof TypeDef) {
            typeInfo.addProperty("kind", "typedef");
            TypeDef td = (TypeDef) dataType;
            typeInfo.addProperty("base_type", td.getDataType().getName());
            typeInfo.addProperty("base_type_path", td.getDataType().getPathName());
        } else if (dataType instanceof FunctionDefinition) {
            typeInfo.addProperty("kind", "functiondef");
        } else if (dataType instanceof Pointer) {
            typeInfo.addProperty("kind", "pointer");
        } else if (dataType instanceof Array) {
            typeInfo.addProperty("kind", "array");
        } else {
            typeInfo.addProperty("kind", "other");
        }

        return typeInfo;
    }

    private JsonObject handleTypeCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "definition");
        if (typeName == null) typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        // This only ever creates an empty struct named `typeName` -- it does
        // NOT parse a C-style struct body. Reject anything that isn't a bare
        // identifier instead of silently creating a type literally named
        // after the whole (unparsed) string, e.g. `struct Foo {}` -- that
        // used to succeed and leave a garbage type behind with no error.
        if (!typeName.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            return errorResult("Invalid type name: '" + typeName + "'. `type create` takes a "
                + "bare identifier and always creates an empty struct; build fields afterward "
                + "with `type add-field`. It does not parse a C-style struct definition.");
        }

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create type");
            try {
                StructureDataType newStruct = new StructureDataType(typeName, 0);
                dtm.addDataType(newStruct, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", typeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeApply(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String typeName = getArgString(args, "type_name");
        boolean force = getArgBool(args, "force", false);
        if (addressStr == null || typeName == null) {
            return errorResult("Address and type_name required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataType dataType = resolveDataType(typeName);
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            // Captured before the clear below (which can silently remove the Function
            // object along with its code) so a `--force` that lands on a function's own
            // entry -- rather than an actual conflicting data unit -- is still reported.
            ghidra.program.model.listing.Function forcedFunctionEntry = force
                ? currentProgram.getFunctionManager().getFunctionAt(addr)
                : null;

            Listing listing = currentProgram.getListing();
            int txId = currentProgram.startTransaction("Apply type");
            try {
                if (force) {
                    int len = dataType.getLength();
                    Address clearEnd = len > 0 ? addr.add(len - 1) : addr;
                    listing.clearCodeUnits(addr, clearEnd, false);
                }
                listing.createData(addr, dataType);
                currentProgram.endTransaction(txId, true);
            } catch (ghidra.program.model.util.CodeUnitInsertionException e) {
                currentProgram.endTransaction(txId, true);
                return typeApplyConflictError(addr, typeName, e);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", addressStr);
            result.addProperty("type", typeName);
            if (force) {
                result.addProperty("cleared_conflicting", true);
                // `--force` means force: clearing a function's own entry point (as opposed
                // to an actual conflicting data unit) "succeeds" the same way, but silently
                // -- `function get` still reports the function's old name/size afterward,
                // and only a later `function disasm` failing with "No instruction at
                // address" exposes the corruption. Flag it here instead.
                if (forcedFunctionEntry != null) {
                    result.addProperty("is_function_entry", true);
                    result.addProperty("warning", "Cleared the entry point of function '"
                        + forcedFunctionEntry.getName() + "' (code, not a conflicting data "
                        + "unit) and replaced it with " + typeName
                        + " data -- the function's code is gone, not just its conflicting bytes.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to apply type: " + e.getMessage());
        }
    }

    /** Surface the conflicting code unit's own type/length/range instead of just "Conflicting data exists". */
    private JsonObject typeApplyConflictError(Address addr, String typeName, Exception cause) {
        Listing listing = currentProgram.getListing();
        CodeUnit cu = listing.getCodeUnitContaining(addr);

        JsonObject detail = new JsonObject();
        String description = "unknown";
        if (cu != null) {
            detail.addProperty("conflicting_start", cu.getMinAddress().toString());
            detail.addProperty("conflicting_end", cu.getMaxAddress().toString());
            detail.addProperty("conflicting_length", cu.getLength());
            if (cu instanceof Instruction) {
                detail.addProperty("conflicting_kind", "instruction");
                detail.addProperty("conflicting_mnemonic", ((Instruction) cu).getMnemonicString());
                description = "an instruction (" + ((Instruction) cu).getMnemonicString() + ")";
            } else if (cu instanceof Data) {
                Data d = (Data) cu;
                detail.addProperty("conflicting_kind", "data");
                detail.addProperty("conflicting_type", d.getDataType().getName());
                detail.addProperty("conflicting_defined", d.isDefined());
                description = (d.isDefined() ? "defined data of type " + d.getDataType().getName()
                    : "undefined data") + " spanning " + cu.getMinAddress() + "-" + cu.getMaxAddress();
            }
        }

        JsonObject err = errorResult("Conflicting data exists at " + addr + " for type " + typeName
            + ": conflicts with " + description + ". Use --force to clear the conflicting range first.");
        err.add("detail", detail);
        return err;
    }

    /**
     * Common C spellings that aren't registered under that literal name in
     * Ghidra's data type managers (fixed-width stdint names, "unsigned X")
     * -- mapped to the canonical Ghidra builtin name that resolveDataType()
     * can find directly.
     */
    private static final Map<String, String> TYPE_NAME_ALIASES = buildTypeNameAliases();

    private static Map<String, String> buildTypeNameAliases() {
        Map<String, String> m = new HashMap<>();
        m.put("uint8_t", "byte");
        m.put("u8", "byte");
        m.put("int8_t", "sbyte");
        m.put("s8", "sbyte");
        m.put("uint16_t", "ushort");
        m.put("u16", "ushort");
        m.put("int16_t", "short");
        m.put("s16", "short");
        m.put("uint32_t", "uint");
        m.put("u32", "uint");
        m.put("int32_t", "int");
        m.put("s32", "int");
        m.put("uint64_t", "ulonglong");
        m.put("u64", "ulonglong");
        m.put("int64_t", "longlong");
        m.put("s64", "longlong");
        m.put("unsigned", "uint");
        m.put("unsigned int", "uint");
        m.put("unsigned long", "ulong");
        m.put("unsigned long long", "ulonglong");
        m.put("unsigned short", "ushort");
        m.put("unsigned char", "uchar");
        m.put("signed char", "char");
        return m;
    }

    private DataType resolveDataType(String name) {
        if (name == null || name.isEmpty()) return null;
        String trimmed = name.trim();
        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Try by path first (e.g., "/int" or "/myCategory/myStruct")
        DataType dt = dtm.getDataType(trimmed);
        if (dt != null) return dt;

        // Handle pointer syntax: "int *" or "char **" -- peel one level and
        // recurse so aliasing/builtin fallback below also applies to the
        // pointee (e.g. "void *", "uint32_t *").
        if (trimmed.endsWith("*")) {
            String base = trimmed.substring(0, trimmed.lastIndexOf('*')).trim();
            DataType baseType = resolveDataType(base);
            return baseType != null ? new PointerDataType(baseType) : null;
        }

        // Scan by simple name: the program's own data type manager first,
        // then Ghidra's built-in primitives (int, uint, dword, qword, ulong,
        // byte, ...). Built-ins usually aren't materialized in the
        // program's own DTM until something references them, so scanning
        // only currentProgram.getDataTypeManager() misses most of the
        // ordinary C type names a user would type.
        DataType found = findDataTypeByName(dtm, trimmed);
        if (found == null) {
            found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), trimmed);
        }
        if (found != null) return found;

        // Retry under the canonical alias (uint32_t -> uint, u32 -> uint, etc.)
        String canonical = TYPE_NAME_ALIASES.get(trimmed);
        if (canonical != null) {
            found = findDataTypeByName(dtm, canonical);
            if (found == null) {
                found = findDataTypeByName(BuiltInDataTypeManager.getDataTypeManager(), canonical);
            }
        }
        return found;
    }

    private DataType findDataTypeByName(DataTypeManager mgr, String name) {
        Iterator<DataType> iter = mgr.getAllDataTypes();
        while (iter.hasNext()) {
            DataType c = iter.next();
            if (c.getName().equals(name)) return c;
        }
        return null;
    }

    private JsonObject handleTypeDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "name");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required");

        try {
            DataType dataType = resolveDataType(typeName);
            if (dataType == null) return errorResult("Type not found: " + typeName);

            String fullPath = dataType.getPathName();
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Delete type");
            try {
                boolean removed = dtm.remove(dataType, monitor);
                currentProgram.endTransaction(txId, true);
                if (!removed) {
                    return errorResult("Failed to remove type: " + typeName + " (may be in use or built-in)");
                }
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", typeName);
            result.addProperty("path", fullPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String oldName = getArgString(args, "old_name");
        String newName = getArgString(args, "new_name");
        if (oldName == null || oldName.isEmpty()) return errorResult("Old type name required");
        if (newName == null || newName.isEmpty()) return errorResult("New type name required");

        try {
            DataType dataType = resolveDataType(oldName);
            if (dataType == null) return errorResult("Type not found: " + oldName);

            int txId = currentProgram.startTransaction("Rename type");
            try {
                dataType.setName(newName);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", newName);
            result.addProperty("path", dataType.getPathName());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename type: " + e.getMessage());
        }
    }

    private JsonObject handleTypeCreateEnum(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String valuesStr = getArgString(args, "values");
        int size = getArgInt(args, "size", 4);
        if (name == null || valuesStr == null) return errorResult("name and values required");

        if (size != 1 && size != 2 && size != 4 && size != 8)
            return errorResult("Enum size must be 1, 2, 4, or 8");

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create enum");
            try {
                EnumDataType enumDt = new EnumDataType(name, size);
                String[] pairs = valuesStr.split(",");
                for (String pair : pairs) {
                    String[] kv = pair.trim().split("=", 2);
                    if (kv.length != 2)
                        throw new IllegalArgumentException("Invalid KEY=VALUE pair: " + pair.trim());
                    String key = kv[0].trim();
                    long value = Long.decode(kv[1].trim());
                    enumDt.add(key, value);
                }
                dtm.addDataType(enumDt, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "enum");
            result.addProperty("size", size);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create enum: " + e.getMessage());
        }
    }

    private JsonObject handleTypeTypedef(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String baseTypeName = getArgString(args, "base_type");
        if (name == null || baseTypeName == null) return errorResult("name and base_type required");

        try {
            DataType baseType = resolveDataType(baseTypeName);
            if (baseType == null) return errorResult("Base type not found: " + baseTypeName);

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create typedef");
            try {
                TypedefDataType td = new TypedefDataType(name, baseType);
                dtm.addDataType(td, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", name);
            result.addProperty("kind", "typedef");
            result.addProperty("base_type", baseTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create typedef: " + e.getMessage());
        }
    }

    private JsonObject handleTypeAddField(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        String fieldTypeName = getArgString(args, "field_type");
        if (typeName == null || fieldName == null || fieldTypeName == null)
            return errorResult("type_name, field_name, and field_type required");

        try {
            DataType structType = resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            DataType fieldDataType = resolveDataType(fieldTypeName);
            if (fieldDataType == null) return errorResult("Field type not found: " + fieldTypeName);

            Structure struct = (Structure) structType;
            int txId = currentProgram.startTransaction("Add field to struct");
            try {
                int offset = getArgInt(args, "offset", -1);
                if (offset >= 0) {
                    // replaceAtOffset() places the field at that exact byte offset,
                    // never shifting components that sit elsewhere -- insertAtOffset()
                    // instead shifts every later field by the new field's size, which
                    // silently corrupts a struct being built (or patched) offset-by-offset
                    // out of order. Unlike insertAtOffset(), replaceAtOffset() does not
                    // grow the structure itself, so grow it first when the field falls
                    // past the current end (the common case: fields added in ascending
                    // offset order into a struct that's only as big as its last field).
                    int fieldSize = getArgInt(args, "size", fieldDataType.getLength());
                    // A brand-new struct (StructureDataType(name, 0)) has zero real
                    // components but getLength() still reports 1 (Ghidra's minimum
                    // displayable data type length) rather than the true internal 0 --
                    // growing off that reported length silently comes up 1 byte short
                    // for the first field. Use 0 as the starting length until a
                    // component actually exists, when getLength() is accurate.
                    int currentLength = struct.getNumComponents() == 0 ? 0 : struct.getLength();
                    int needed = (offset + fieldSize) - currentLength;
                    if (needed > 0) {
                        struct.growStructure(needed);
                    }
                    struct.replaceAtOffset(offset, fieldDataType, fieldSize, fieldName, null);
                } else {
                    struct.add(fieldDataType, fieldName, null);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_added");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            result.addProperty("field_type", fieldTypeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add field: " + e.getMessage());
        }
    }

    private JsonObject handleTypeDelField(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String typeName = getArgString(args, "type_name");
        String fieldName = getArgString(args, "field_name");
        if (typeName == null || fieldName == null)
            return errorResult("type_name and field_name required");

        try {
            DataType structType = resolveDataType(typeName);
            if (structType == null) return errorResult("Type not found: " + typeName);
            if (!(structType instanceof Structure))
                return errorResult("Type is not a struct: " + typeName);

            Structure struct = (Structure) structType;
            int ordinal = -1;
            for (DataTypeComponent comp : struct.getComponents()) {
                if (fieldName.equals(comp.getFieldName())) {
                    ordinal = comp.getOrdinal();
                    break;
                }
            }
            if (ordinal < 0)
                return errorResult("Field not found: " + fieldName + " in " + typeName);

            int txId = currentProgram.startTransaction("Delete field from struct");
            try {
                struct.delete(ordinal);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "field_deleted");
            result.addProperty("struct", typeName);
            result.addProperty("field", fieldName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete field: " + e.getMessage());
        }
    }

    // --- Function Tag Handlers ---

    // Exact (case-sensitive) name order for all serialized tag lists. Do NOT use
    // FunctionTag's Comparable — it is case-insensitive name-then-comment, and
    // mixing collations would order Crypto/crypto differently across commands.
    private static final Comparator<FunctionTag> TAG_NAME_ORDER =
        Comparator.comparing(FunctionTag::getName);

    private JsonObject tagToJson(FunctionTag tag, FunctionTagManager tm) {
        JsonObject o = new JsonObject();
        o.addProperty("name", tag.getName());
        o.addProperty("comment", tag.getComment());
        o.addProperty("use_count", tm.getUseCount(tag));
        return o;
    }

    // Sorted tag-name array for function rows. getTags() returns the function's
    // LIVE cached set — copy names out, never mutate it.
    private JsonArray functionTagNames(Function func) {
        List<String> names = new ArrayList<>();
        for (FunctionTag t : func.getTags()) names.add(t.getName());
        Collections.sort(names);
        JsonArray arr = new JsonArray();
        for (String n : names) arr.add(n);
        return arr;
    }

    // Validation applies at creation points only (tag_create, tag_rename's new
    // name, tag_add's to-create names). Existing tags — including odd names
    // created in the Ghidra GUI — must stay attachable/removable/deletable.
    private String validateTagName(String name) {
        if (name == null || name.trim().isEmpty()) return "Tag name cannot be empty";
        if (name.contains(",")) return "Tag name cannot contain ',' (Ghidra GUI tag separator): " + name;
        if (name.contains(";")) return "Tag name cannot contain ';' (CSV array separator): " + name;
        return null;
    }

    private String tagNotFoundError(String name, FunctionTagManager tm) {
        StringBuilder msg = new StringBuilder("No tag named '").append(name).append("'");
        List<String> near = new ArrayList<>();
        for (FunctionTag t : tm.getAllFunctionTags()) {
            if (t.getName().equalsIgnoreCase(name) && !t.getName().equals(name)) {
                near.add(t.getName());
            }
        }
        if (near.isEmpty() && name.length() >= 3) {
            for (FunctionTag t : tm.getAllFunctionTags()) {
                if (levenshteinDistance(t.getName().toLowerCase(), name.toLowerCase()) <= 2) {
                    near.add(t.getName());
                }
            }
        }
        if (!near.isEmpty()) {
            Collections.sort(near);
            msg.append(". Did you mean '").append(near.get(0)).append("'?");
        }
        return msg.toString();
    }

    private JsonObject handleTagList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        int limit = getArgInt(args, "limit", 0);
        String funcTarget = getArgString(args, "function");
        FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();

        List<FunctionTag> all;
        if (funcTarget != null) {
            Function func = findFunctionByNameOrAddress(funcTarget);
            if (func == null) return errorResult(buildFunctionTargetHint(funcTarget));
            all = new ArrayList<>(func.getTags());          // copy the live set
        } else {
            // getAllFunctionTags() returns DB record (creation) order — not sorted.
            all = new ArrayList<>(tm.getAllFunctionTags());
        }
        // Sort BEFORE applying limit, or --limit N truncates by creation order.
        all.sort(TAG_NAME_ORDER);

        JsonArray tags = new JsonArray();
        for (FunctionTag t : all) {
            if (limit > 0 && tags.size() >= limit) break;
            tags.add(tagToJson(t, tm));
        }
        JsonObject result = new JsonObject();
        result.add("tags", tags);
        result.addProperty("count", tags.size());
        return result;
    }

    private JsonObject handleTagGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");
        int limit = getArgInt(args, "limit", 0);

        FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
        FunctionTag tag = tm.getFunctionTag(name);
        if (tag == null) return errorResult(tagNotFoundError(name, tm));

        JsonArray functions = new JsonArray();
        if (tm.getUseCount(tag) > 0) {
            // No public reverse index in Ghidra; linear scan like Ghidra's own
            // Function Tags window. Non-external functions only (§7a policy).
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            while (iter.hasNext()) {
                if (limit > 0 && functions.size() >= limit) break;
                Function func = iter.next();
                if (func.getTags().contains(tag)) {
                    JsonObject o = new JsonObject();
                    o.addProperty("name", func.getName());
                    o.addProperty("address", func.getEntryPoint().toString());
                    functions.add(o);
                }
            }
        }
        // Envelope constraint: "target"/"count" are META_KEYS on the Rust side,
        // so this unwraps to member-function rows. Do not add non-meta keys
        // (comment/use_count live in tag_list).
        JsonObject result = new JsonObject();
        result.addProperty("target", name);
        result.add("functions", functions);
        result.addProperty("count", functions.size());
        return result;
    }

    private JsonObject handleTagCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String comment = getArgString(args, "comment");
        if (name == null) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
            FunctionTag existing = tm.getFunctionTag(name);
            if (existing != null) {
                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", existing.getName());
                result.addProperty("comment", existing.getComment());
                result.addProperty("existed", true);
                return result;
            }

            String err = validateTagName(name);
            if (err != null) return errorResult(err);

            int txId = currentProgram.startTransaction("Create function tag");
            FunctionTag tag;
            try {
                tag = tm.createFunctionTag(name, comment == null ? "" : comment);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "created");
            result.addProperty("name", tag.getName());
            result.addProperty("comment", tag.getComment());
            result.addProperty("existed", false);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to create tag: " + e.getMessage());
        }
    }

    private JsonObject handleTagDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(tagNotFoundError(name, tm));

            // Capture BOTH counts before delete: use_count is Ghidra's raw number
            // (may include external functions); functions_affected is the
            // non-external membership consistent with what `tag get` shows.
            int useCount = tm.getUseCount(tag);
            int functionsAffected = 0;
            if (useCount > 0) {
                FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
                while (iter.hasNext()) {
                    if (iter.next().getTags().contains(tag)) functionsAffected++;
                }
            }

            int txId = currentProgram.startTransaction("Delete function tag");
            try {
                tag.delete();                 // global: detaches from ALL functions
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", name);
            result.addProperty("use_count", useCount);
            result.addProperty("functions_affected", functionsAffected);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete tag: " + e.getMessage());
        }
    }

    private JsonObject handleTagRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String newName = getArgString(args, "new_name");
        if (name == null || newName == null || name.isEmpty())
            return errorResult("name and new_name required");

        try {
            FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(tagNotFoundError(name, tm));
            if (tm.getFunctionTag(newName) != null)
                return errorResult("Tag already exists: '" + newName + "'");

            String err = validateTagName(newName);
            if (err != null) return errorResult(err);

            int useCount = tm.getUseCount(tag);
            int txId = currentProgram.startTransaction("Rename function tag");
            try {
                tag.setName(newName);         // global rename; functions store the id
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("old_name", name);
            result.addProperty("new_name", newName);
            result.addProperty("use_count", useCount);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to rename tag: " + e.getMessage());
        }
    }

    private JsonObject handleTagSetComment(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String name = getArgString(args, "name");
        String comment = getArgString(args, "comment");
        if (name == null || name.isEmpty()) return errorResult("Tag name required");

        try {
            FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
            FunctionTag tag = tm.getFunctionTag(name);
            if (tag == null) return errorResult(tagNotFoundError(name, tm));

            int txId = currentProgram.startTransaction("Set function tag comment");
            try {
                tag.setComment(comment == null ? "" : comment);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "comment_set");
            result.addProperty("name", name);
            result.addProperty("comment", comment == null ? "" : comment);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set tag comment: " + e.getMessage());
        }
    }

    private JsonObject handleTagAdd(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        String[] rawTags = getArgStringArray(args, "tags");
        boolean noCreate = getArgBool(args, "no_create", false);
        if (target == null || rawTags.length == 0)
            return errorResult("function and tags are required");

        try {
            // Dedupe argv up front: `tag add f crypto crypto` must not double-report.
            LinkedHashSet<String> tagNames = new LinkedHashSet<>(Arrays.asList(rawTags));
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            FunctionTagManager tm = currentProgram.getFunctionManager().getFunctionTagManager();
            Set<String> current = new HashSet<>();
            for (FunctionTag t : func.getTags()) current.add(t.getName());

            List<String> toCreate = new ArrayList<>();
            for (String name : tagNames) {
                if (tm.getFunctionTag(name) != null) continue;  // existing: any name attachable
                String err = validateTagName(name);             // validate only names we'd CREATE
                if (err != null) return errorResult(err);
                toCreate.add(name);
            }
            if (noCreate && !toCreate.isEmpty())
                return errorResult("Tags do not exist (--no-create): " + String.join(", ", toCreate));

            JsonArray added = new JsonArray(), created = new JsonArray(), already = new JsonArray();
            int txId = currentProgram.startTransaction("Add function tags");
            try {
                for (String name : tagNames) {
                    if (current.contains(name)) { already.add(name); continue; }
                    func.addTag(name);   // auto-creates; returns true unconditionally
                    added.add(name);
                    if (toCreate.contains(name)) created.add(name);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tagged");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.add("added", added);
            result.add("created", created);
            result.add("already_present", already);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add tags: " + e.getMessage());
        }
    }

    private JsonObject handleTagRemove(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "function");
        String[] rawTags = getArgStringArray(args, "tags");
        boolean all = getArgBool(args, "all", false);
        if (target == null || (rawTags.length == 0 && !all))
            return errorResult("function and tags (or all) are required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            // Pre-read into a COPY: getTags() is the live set and removeTag
            // mutates it — iterating it directly while removing throws CME.
            List<String> currentNames = new ArrayList<>();
            for (FunctionTag t : func.getTags()) currentNames.add(t.getName());
            Set<String> current = new HashSet<>(currentNames);

            LinkedHashSet<String> tagNames = all
                ? new LinkedHashSet<>(currentNames)
                : new LinkedHashSet<>(Arrays.asList(rawTags));

            JsonArray removed = new JsonArray(), notPresent = new JsonArray();
            int txId = currentProgram.startTransaction("Remove function tags");
            try {
                for (String name : tagNames) {
                    if (current.contains(name)) {
                        func.removeTag(name);   // void; silent — membership pre-checked
                        removed.add(name);
                    } else {
                        notPresent.add(name);
                    }
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "untagged");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.add("removed", removed);
            result.add("not_present", notPresent);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to remove tags: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetSignature(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String sigStr = getArgString(args, "signature");
        if (target == null || sigStr == null) return errorResult("target and signature required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            // Parse the signature using Ghidra's headless-friendly signature parser.
            // FunctionSignatureParser works without a PluginTool/ServiceProvider
            // (the DataTypeQueryService arg may be null), so it is safe in headless.
            ghidra.app.util.parser.FunctionSignatureParser sigParser =
                new ghidra.app.util.parser.FunctionSignatureParser(
                    currentProgram.getDataTypeManager(), null);
            ghidra.program.model.data.FunctionDefinitionDataType funcDef =
                sigParser.parse(func.getSignature(), sigStr);

            if (funcDef == null) {
                return errorResult("Failed to parse signature: " + sigStr);
            }

            int txId = currentProgram.startTransaction("Set function signature");
            try {
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    func.getEntryPoint(), funcDef, SourceType.USER_DEFINED);
                cmd.applyTo(currentProgram);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            String newSig = null;
            try { newSig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "signature_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            if (newSig != null) {
                result.addProperty("signature", newSig);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set signature: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetReturnType(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String returnTypeName = getArgString(args, "return_type");
        if (target == null || returnTypeName == null)
            return errorResult("target and return_type required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            DataType returnType = resolveDataType(returnTypeName);
            if (returnType == null)
                return errorResult("Return type not found: " + returnTypeName);

            int txId = currentProgram.startTransaction("Set return type");
            try {
                func.setReturnType(returnType, SourceType.USER_DEFINED);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "return_type_set");
            result.addProperty("function", func.getName());
            result.addProperty("return_type", returnTypeName);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set return type: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetCallingConvention(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String convention = getArgString(args, "convention");
        if (target == null || convention == null)
            return errorResult("target and convention required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Set calling convention");
            try {
                func.setCallingConvention(convention);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            String sig = null;
            try { sig = func.getPrototypeString(false, false); } catch (Exception e) {}

            JsonObject result = new JsonObject();
            result.addProperty("status", "calling_convention_set");
            result.addProperty("function", func.getName());
            result.addProperty("calling_convention", convention);
            if (sig != null) result.addProperty("signature", sig);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set calling convention: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionSetNoReturn(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        boolean value = getArgBool(args, "value", true);
        if (target == null || target.isEmpty()) return errorResult("target required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Set no-return");
            try {
                func.setNoReturn(value);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "noreturn_set");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("no_return", func.hasNoReturn());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set no-return: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionTagAdd(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String tagName = getArgString(args, "tag_name");
        if (target == null || target.isEmpty()) return errorResult("target required");
        if (tagName == null || tagName.isEmpty()) return errorResult("tag_name required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Add function tag");
            try {
                func.addTag(tagName);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tag_added");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("tag", tagName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to add tag: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionTagRemove(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");
        String tagName = getArgString(args, "tag_name");
        if (target == null || target.isEmpty()) return errorResult("target required");
        if (tagName == null || tagName.isEmpty()) return errorResult("tag_name required");

        try {
            Function func = findFunctionByNameOrAddress(target);
            if (func == null) return errorResult(buildFunctionTargetHint(target));

            int txId = currentProgram.startTransaction("Remove function tag");
            try {
                func.removeTag(tagName);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "tag_removed");
            result.addProperty("function", func.getName());
            result.addProperty("address", func.getEntryPoint().toString());
            result.addProperty("tag", tagName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to remove tag: " + e.getMessage());
        }
    }

    /** Tags on one function (target given), or every tag definition in the program (no target). */
    private JsonObject handleFunctionTagList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String target = getArgString(args, "target");

        try {
            JsonObject result = new JsonObject();
            if (target != null && !target.isEmpty()) {
                Function func = findFunctionByNameOrAddress(target);
                if (func == null) return errorResult(buildFunctionTargetHint(target));

                JsonArray tags = new JsonArray();
                for (FunctionTag tag : func.getTags()) {
                    JsonObject t = new JsonObject();
                    t.addProperty("name", tag.getName());
                    t.addProperty("comment", tag.getComment());
                    tags.add(t);
                }
                result.addProperty("function", func.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                result.add("tags", tags);
            } else {
                JsonArray tags = new JsonArray();
                FunctionTagManager tagManager = currentProgram.getFunctionManager().getFunctionTagManager();
                for (FunctionTag tag : tagManager.getAllFunctionTags()) {
                    JsonObject t = new JsonObject();
                    t.addProperty("name", tag.getName());
                    t.addProperty("comment", tag.getComment());
                    t.addProperty("use_count", tagManager.getUseCount(tag));
                    tags.add(t);
                }
                result.add("tags", tags);
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list tags: " + e.getMessage());
        }
    }

    private JsonObject handleSetVarType(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");
        String funcTarget = getArgString(args, "function");
        String varName = getArgString(args, "var_name");
        String typeName = getArgString(args, "type_name");
        if (funcTarget == null || funcTarget.isEmpty()) return errorResult("Function target required");
        if (varName == null || varName.isEmpty()) return errorResult("Variable name required (--var)");
        if (typeName == null || typeName.isEmpty()) return errorResult("Type name required (--type)");

        try {
            Function func = findFunctionByNameOrAddress(funcTarget);
            if (func == null) return errorResult(buildFunctionTargetHint(funcTarget));

            DataType newType = resolveDataType(typeName);
            if (newType == null) return errorResult("Type not found: " + typeName);

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                TaskMonitor mon = monitor;
                DecompileResults results = decompiler.decompileFunction(func, 30, mon);
                if (!results.decompileCompleted())
                    return errorResult("Decompilation failed for " + funcTarget);

                ghidra.program.model.pcode.HighFunction highFunc = results.getHighFunction();
                if (highFunc == null)
                    return errorResult("Could not get high-level function representation");

                ghidra.program.model.pcode.LocalSymbolMap lsm = highFunc.getLocalSymbolMap();
                ghidra.program.model.pcode.HighSymbol targetSym = null;
                Iterator<ghidra.program.model.pcode.HighSymbol> symIter = lsm.getSymbols();
                while (symIter.hasNext()) {
                    ghidra.program.model.pcode.HighSymbol sym = symIter.next();
                    if (sym.getName().equals(varName)) {
                        targetSym = sym;
                        break;
                    }
                }

                if (targetSym == null)
                    return errorResult("Variable not found: " + varName + " in function " + func.getName());

                int txId = currentProgram.startTransaction("Set variable type");
                try {
                    HighFunctionDBUtil.updateDBVariable(targetSym, targetSym.getName(), newType, SourceType.USER_DEFINED);
                    currentProgram.endTransaction(txId, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(txId, true);
                    throw e;
                }

                JsonObject result = new JsonObject();
                result.addProperty("status", "updated");
                result.addProperty("function", func.getName());
                result.addProperty("variable", varName);
                result.addProperty("new_type", newType.getName());
                result.addProperty("address", func.getEntryPoint().toString());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to set variable type: " + e.getMessage());
        }
    }

    // --- Comment Handlers ---

    private int resolveCommentType(String typeStr) {
        if (typeStr == null) return CodeUnit.EOL_COMMENT;
        switch (typeStr.toUpperCase()) {
            case "PRE":   return CodeUnit.PRE_COMMENT;
            case "POST":  return CodeUnit.POST_COMMENT;
            case "PLATE": return CodeUnit.PLATE_COMMENT;
            default:      return CodeUnit.EOL_COMMENT;
        }
    }

    private JsonObject handleCommentList(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        Listing listing = currentProgram.getListing();
        Memory memory = currentProgram.getMemory();
        JsonArray comments = new JsonArray();
        int count = 0;

        int[][] commentTypes = {
            {CodeUnit.EOL_COMMENT},
            {CodeUnit.PRE_COMMENT},
            {CodeUnit.POST_COMMENT},
            {CodeUnit.PLATE_COMMENT}
        };
        String[] commentNames = {"EOL", "PRE", "POST", "PLATE"};

        for (MemoryBlock block : memory.getBlocks()) {
            if (limit > 0 && count >= limit) break;

            ghidra.program.model.address.AddressSet addrSet =
                new ghidra.program.model.address.AddressSet(block.getStart(), block.getEnd());

            ghidra.program.model.address.AddressIterator addrIter =
                listing.getCommentAddressIterator(addrSet, true);

            while (addrIter.hasNext()) {
                if (limit > 0 && count >= limit) break;

                Address addr = addrIter.next();
                CodeUnit cu = listing.getCodeUnitAt(addr);
                if (cu == null) continue;

                for (int i = 0; i < commentNames.length; i++) {
                    if (limit > 0 && count >= limit) break;

                    String text = cu.getComment(commentTypes[i][0]);
                    if (text != null) {
                        if (nameFilter != null && !text.toLowerCase().contains(nameFilter.toLowerCase())) {
                            continue;
                        }

                        JsonObject commentObj = new JsonObject();
                        commentObj.addProperty("address", addr.toString());
                        commentObj.addProperty("type", commentNames[i]);
                        commentObj.addProperty("text", text);
                        comments.add(commentObj);
                        count++;
                    }
                }
            }
        }

        JsonObject result = new JsonObject();
        result.add("comments", comments);
        result.addProperty("count", comments.size());
        return result;
    }

    private JsonObject handleCommentGet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            CodeUnit cu = listing.getCodeUnitAt(addr);
            if (cu == null) return errorResult("No code unit at address: " + addressStr);

            int[] types = {CodeUnit.EOL_COMMENT, CodeUnit.PRE_COMMENT, CodeUnit.POST_COMMENT, CodeUnit.PLATE_COMMENT};
            String[] names = {"EOL", "PRE", "POST", "PLATE"};

            JsonArray comments = new JsonArray();
            for (int i = 0; i < types.length; i++) {
                String text = cu.getComment(types[i]);
                if (text != null) {
                    JsonObject commentObj = new JsonObject();
                    commentObj.addProperty("type", names[i]);
                    commentObj.addProperty("text", text);
                    comments.add(commentObj);
                }
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", addressStr);
            result.add("comments", comments);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to get comments: " + e.getMessage());
        }
    }

    private JsonObject handleCommentSet(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String text = getArgString(args, "text");
        String commentTypeStr = getArgString(args, "comment_type");
        // Older clients sent the type under "type"; accept it as a fallback.
        if (commentTypeStr == null) commentTypeStr = getArgString(args, "type");
        if (commentTypeStr == null) commentTypeStr = "EOL";

        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Set<String> validTypes = new HashSet<>(Arrays.asList("EOL", "PRE", "POST", "PLATE"));
            if (!validTypes.contains(commentTypeStr.toUpperCase())) {
                return errorResult("Invalid comment type: " + commentTypeStr + ". Must be one of: EOL, PRE, POST, PLATE");
            }

            int commentType = resolveCommentType(commentTypeStr);
            Listing listing = currentProgram.getListing();

            int txId = currentProgram.startTransaction("Set comment");
            try {
                listing.setComment(addr, commentType, text);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "set");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to set comment: " + e.getMessage());
        }
    }

    private JsonObject handleCommentDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();

            int txId = currentProgram.startTransaction("Delete comments");
            try {
                listing.setComment(addr, CodeUnit.EOL_COMMENT, null);
                listing.setComment(addr, CodeUnit.PRE_COMMENT, null);
                listing.setComment(addr, CodeUnit.POST_COMMENT, null);
                listing.setComment(addr, CodeUnit.PLATE_COMMENT, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("address", addressStr);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to delete comment: " + e.getMessage());
        }
    }

    // --- Graph Handlers ---

    private JsonObject handleGraphCalls(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        int limit = getArgInt(args, "limit", 0);

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        JsonArray nodes = new JsonArray();
        JsonArray edges = new JsonArray();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;
            Function func = iter.next();
            String funcAddr = func.getEntryPoint().toString();

            JsonObject node = new JsonObject();
            node.addProperty("id", funcAddr);
            node.addProperty("name", func.getName());
            node.addProperty("address", funcAddr);
            nodes.add(node);

            ghidra.program.model.address.AddressIterator refSrcIter =
                refMgr.getReferenceSourceIterator(func.getBody(), true);
            while (refSrcIter.hasNext()) {
                Address fromAddr = refSrcIter.next();
                for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Address targetAddr = ref.getToAddress();
                    Function targetFunc = fm.getFunctionAt(targetAddr);
                    if (targetFunc != null) {
                        JsonObject edge = new JsonObject();
                        edge.addProperty("from", funcAddr);
                        edge.addProperty("to", targetAddr.toString());
                        edge.addProperty("type", "call");
                        edges.add(edge);
                    }
                }
                }
            }
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("node_count", nodes.size());
        result.addProperty("edge_count", edges.size());
        return result;
    }

    private Function findFunctionByNameOrAddress(String nameOrAddr) {
        if (currentProgram == null || nameOrAddr == null || nameOrAddr.isEmpty()) {
            return null;
        }

        FunctionManager fm = currentProgram.getFunctionManager();

        // Resolve addresses, symbols, and auto names like FUN_00401234.
        Address addr = resolveAddress(nameOrAddr);
        if (addr != null) {
            Function f = fm.getFunctionContaining(addr);
            if (f != null) {
                return f;
            }
        }

        // Try as name
        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            Function func = iter.next();
            if (func.getName().equals(nameOrAddr)) return func;
        }
        return null;
    }

    private JsonObject handleGraphCallers(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);

        Function targetFunc = findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        JsonArray callers = new JsonArray();
        Set<String> visited = new HashSet<>();

        findCallersRecursive(targetFunc, 0, depth, callers, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callers", callers);
        result.addProperty("count", callers.size());
        return result;
    }

    private void findCallersRecursive(Function func, int currentDepth, int maxDepth,
            JsonArray callers, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
        if (maxDepth > 0 && currentDepth >= maxDepth) return;
        String funcAddrStr = func.getEntryPoint().toString();
        if (visited.contains(funcAddrStr)) return;
        visited.add(funcAddrStr);

        for (Reference ref : refMgr.getReferencesTo(func.getEntryPoint())) {
            if (ref.getReferenceType().isCall()) {
                Address fromAddr = ref.getFromAddress();
                Function callerFunc = fm.getFunctionContaining(fromAddr);
                if (callerFunc != null) {
                    JsonObject callerInfo = new JsonObject();
                    callerInfo.addProperty("name", callerFunc.getName());
                    callerInfo.addProperty("address", callerFunc.getEntryPoint().toString());
                    callerInfo.addProperty("call_site", fromAddr.toString());
                    callerInfo.addProperty("depth", currentDepth);
                    callers.add(callerInfo);

                    if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                        findCallersRecursive(callerFunc, currentDepth + 1, maxDepth, callers, visited, refMgr, fm);
                    }
                }
            }
        }
    }

    private JsonObject handleGraphCallees(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String funcName = getArgString(args, "function");
        if (funcName == null) return errorResult("Function name required");
        int depth = getArgInt(args, "depth", 1);

        Function targetFunc = findFunctionByNameOrAddress(funcName);
        if (targetFunc == null) return errorResult(buildFunctionTargetHint(funcName));

        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        JsonArray callees = new JsonArray();
        Set<String> visited = new HashSet<>();

        findCalleesRecursive(targetFunc, 0, depth, callees, visited, refMgr, fm);

        JsonObject result = new JsonObject();
        result.addProperty("function", funcName);
        result.add("callees", callees);
        result.addProperty("count", callees.size());
        return result;
    }

    private void findCalleesRecursive(Function func, int currentDepth, int maxDepth,
            JsonArray callees, Set<String> visited, ReferenceManager refMgr, FunctionManager fm) {
        if (maxDepth > 0 && currentDepth >= maxDepth) return;
        String funcAddrStr = func.getEntryPoint().toString();
        if (visited.contains(funcAddrStr)) return;
        visited.add(funcAddrStr);

        ghidra.program.model.address.AddressIterator refSrcIter =
            refMgr.getReferenceSourceIterator(func.getBody(), true);
        while (refSrcIter.hasNext()) {
            Address fromAddr = refSrcIter.next();
            for (Reference ref : refMgr.getReferencesFrom(fromAddr)) {
                if (ref.getReferenceType().isCall()) {
                    Address toAddr = ref.getToAddress();
                    Function calleeFunc = fm.getFunctionAt(toAddr);
                    if (calleeFunc != null) {
                        JsonObject calleeInfo = new JsonObject();
                        calleeInfo.addProperty("name", calleeFunc.getName());
                        calleeInfo.addProperty("address", calleeFunc.getEntryPoint().toString());
                        calleeInfo.addProperty("call_site", ref.getFromAddress().toString());
                        calleeInfo.addProperty("depth", currentDepth);
                        callees.add(calleeInfo);

                        if (maxDepth == 0 || currentDepth + 1 < maxDepth) {
                            findCalleesRecursive(calleeFunc, currentDepth + 1, maxDepth, callees, visited, refMgr, fm);
                        }
                    }
                }
            }
        }
    }

    private JsonObject handleGraphExport(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String format = getArgString(args, "format");
        if (format == null) format = "json";

        // Build graph first
        JsonObject graphData = handleGraphCalls(new JsonObject());
        if (graphData.has("error")) return graphData;

        if ("json".equals(format)) {
            return graphData;
        } else if ("dot".equals(format)) {
            StringBuilder sb = new StringBuilder();
            sb.append("digraph CallGraph {\n");
            sb.append("  rankdir=LR;\n");
            sb.append("  node [shape=box];\n");

            JsonArray nodes = graphData.getAsJsonArray("nodes");
            for (int i = 0; i < nodes.size(); i++) {
                JsonObject node = nodes.get(i).getAsJsonObject();
                String nodeId = node.get("id").getAsString().replace(":", "_");
                String label = node.get("name").getAsString();
                sb.append("  \"").append(nodeId).append("\" [label=\"").append(label).append("\"];\n");
            }

            JsonArray edges = graphData.getAsJsonArray("edges");
            for (int i = 0; i < edges.size(); i++) {
                JsonObject edge = edges.get(i).getAsJsonObject();
                String fromId = edge.get("from").getAsString().replace(":", "_");
                String toId = edge.get("to").getAsString().replace(":", "_");
                sb.append("  \"").append(fromId).append("\" -> \"").append(toId).append("\";\n");
            }

            sb.append("}");

            JsonObject result = new JsonObject();
            result.addProperty("format", "dot");
            result.addProperty("output", sb.toString());
            return result;
        } else {
            return errorResult("Unsupported format: " + format);
        }
    }

    // --- Diff Handlers ---

    private JsonObject handleDiffPrograms(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String prog1 = getArgString(args, "program1");
        String prog2 = getArgString(args, "program2");
        if (prog1 == null) prog1 = "";
        if (prog2 == null) prog2 = "";

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            Memory memory = currentProgram.getMemory();
            SymbolTable symbolTable = currentProgram.getSymbolTable();

            JsonObject prog1Stats = new JsonObject();
            prog1Stats.addProperty("name", prog1);
            prog1Stats.addProperty("function_count", fm.getFunctionCount());
            prog1Stats.addProperty("memory_size", memory.getSize());
            prog1Stats.addProperty("symbol_count", symbolTable.getNumSymbols());

            JsonArray memBlocks = new JsonArray();
            for (MemoryBlock block : memory.getBlocks()) {
                JsonObject blockObj = new JsonObject();
                blockObj.addProperty("name", block.getName());
                blockObj.addProperty("start", block.getStart().toString());
                blockObj.addProperty("end", block.getEnd().toString());
                blockObj.addProperty("size", block.getSize());
                memBlocks.add(blockObj);
            }
            prog1Stats.add("memory_blocks", memBlocks);

            JsonObject prog2Stats = new JsonObject();
            prog2Stats.addProperty("name", prog2);
            prog2Stats.addProperty("note", "Comparison requires loading second program");

            JsonObject result = new JsonObject();
            result.add("program1", prog1Stats);
            result.add("program2", prog2Stats);
            result.addProperty("status", "partial");
            result.addProperty("message", "Single program stats returned (multi-program comparison not implemented)");
            return result;
        } catch (Exception e) {
            return errorResult("Failed to diff programs: " + e.getMessage());
        }
    }

    private JsonObject handleDiffFunctions(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String func1Target = getArgString(args, "func1");
        String func2Target = getArgString(args, "func2");
        if (func1Target == null || func2Target == null) {
            return errorResult("func1 and func2 required");
        }

        try {
            Function func1 = findFunctionByNameOrAddress(func1Target);
            Function func2 = findFunctionByNameOrAddress(func2Target);

            if (func1 == null) return errorResult(buildFunctionTargetHint(func1Target));
            if (func2 == null) return errorResult(buildFunctionTargetHint(func2Target));

            DecompInterface decompiler = new DecompInterface();
            try {
                decompiler.openProgram(currentProgram);
                TaskMonitor mon = monitor;

                DecompileResults res1 = decompiler.decompileFunction(func1, 30, mon);
                DecompileResults res2 = decompiler.decompileFunction(func2, 30, mon);

                if (!res1.decompileCompleted()) return errorResult("Failed to decompile " + func1Target);
                if (!res2.decompileCompleted()) return errorResult("Failed to decompile " + func2Target);

                String code1 = res1.getDecompiledFunction().getC();
                String code2 = res2.getDecompiledFunction().getC();

                String[] lines1 = code1.split("\n");
                String[] lines2 = code2.split("\n");

                JsonArray diffLines = new JsonArray();
                int maxLines = Math.max(lines1.length, lines2.length);
                for (int i = 0; i < maxLines; i++) {
                    String l1 = i < lines1.length ? lines1[i] : "";
                    String l2 = i < lines2.length ? lines2[i] : "";
                    if (!l1.equals(l2)) {
                        JsonObject diff = new JsonObject();
                        diff.addProperty("line", i + 1);
                        diff.addProperty("func1", l1);
                        diff.addProperty("func2", l2);
                        diff.addProperty("status", "changed");
                        diffLines.add(diff);
                    }
                }

                JsonObject f1Info = new JsonObject();
                f1Info.addProperty("name", func1.getName());
                f1Info.addProperty("lines", lines1.length);
                f1Info.addProperty("code", code1);

                JsonObject f2Info = new JsonObject();
                f2Info.addProperty("name", func2.getName());
                f2Info.addProperty("lines", lines2.length);
                f2Info.addProperty("code", code2);

                JsonObject result = new JsonObject();
                result.add("func1", f1Info);
                result.add("func2", f2Info);
                result.add("differences", diffLines);
                result.addProperty("diff_count", diffLines.size());
                return result;
            } finally {
                decompiler.dispose();
            }
        } catch (Exception e) {
            return errorResult("Failed to diff functions: " + e.getMessage());
        }
    }

    // --- Patch Handlers ---

    private JsonObject handlePatchBytes(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        String hexData = getArgString(args, "hex");
        if (addressStr == null || hexData == null) {
            return errorResult("Address and hex data required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            String hexClean = hexData.replace("0x", "").replace(" ", "");
            byte[] patchData = new byte[hexClean.length() / 2];
            for (int i = 0; i < patchData.length; i++) {
                patchData[i] = (byte) Integer.parseInt(hexClean.substring(i * 2, i * 2 + 2), 16);
            }

            Memory memory = currentProgram.getMemory();
            Listing listing = currentProgram.getListing();
            int txId = currentProgram.startTransaction("Patch bytes");
            try {
                // Clear any existing instructions/data at the target range
                // so memory.setBytes doesn't conflict
                Address endAddr = addr.add(patchData.length - 1);
                listing.clearCodeUnits(addr, endAddr, false);
                memory.setBytes(addr, patchData);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "patched");
            result.addProperty("address", addr.toString());
            result.addProperty("bytes", patchData.length);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to patch bytes: " + e.getMessage());
        }
    }

    private JsonObject handlePatchNop(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        if (addressStr == null) return errorResult("Address required");

        int count = getArgInt(args, "count", 1);
        if (count < 1) return errorResult("count must be >= 1");

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            Memory memory = currentProgram.getMemory();
            String processor = currentProgram.getLanguage().getProcessor().toString();
            byte nopByte = processor.toLowerCase().contains("x86") ? (byte) 0x90 : (byte) 0x00;

            JsonArray nopped = new JsonArray();
            int totalBytes = 0;
            int txId = currentProgram.startTransaction("NOP instructions");
            try {
                Address cur = addr;
                for (int i = 0; i < count; i++) {
                    Instruction instruction = listing.getInstructionAt(cur);
                    if (instruction == null) {
                        // Roll back partial work so the program is left untouched.
                        currentProgram.endTransaction(txId, true);
                        return errorResult("No instruction at address: " + cur.toString()
                            + " (NOP'd " + nopped.size() + " of " + count + ")");
                    }

                    int instrLength = instruction.getLength();
                    // Capture the next instruction's address before we clear this one.
                    Address next = cur.add(instrLength);

                    byte[] nopBytes = new byte[instrLength];
                    Arrays.fill(nopBytes, nopByte);
                    listing.clearCodeUnits(cur, cur.add(instrLength - 1), false);
                    memory.setBytes(cur, nopBytes);

                    JsonObject entry = new JsonObject();
                    entry.addProperty("address", cur.toString());
                    entry.addProperty("bytes", instrLength);
                    nopped.add(entry);
                    totalBytes += instrLength;
                    cur = next;
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "nopped");
            result.addProperty("address", addr.toString());
            result.addProperty("count", nopped.size());
            result.addProperty("bytes", totalBytes);
            result.add("instructions", nopped);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to NOP instruction: " + e.getMessage());
        }
    }

    private JsonObject handlePatchExport(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String outputPath = getArgString(args, "output");
        if (outputPath == null || outputPath.isEmpty()) {
            return errorResult("Output path required");
        }

        try {
            // Use reflection to access BinaryExporter which may not always be available.
            // The base Exporter.export() declares its second parameter as DomainObject
            // (not Program), and the exact signature has drifted across Ghidra versions,
            // so resolve the method by name + 4-arg arity rather than exact param types
            // (a hardcoded Program.class lookup throws NoSuchMethodException on Ghidra 12).
            Class<?> exporterClass = Class.forName("ghidra.app.util.exporter.BinaryExporter");
            Object exporter = exporterClass.getDeclaredConstructor().newInstance();

            java.lang.reflect.Method exportMethod = null;
            for (java.lang.reflect.Method m : exporterClass.getMethods()) {
                if (m.getName().equals("export") && m.getParameterCount() == 4) {
                    exportMethod = m;
                    break;
                }
            }
            if (exportMethod == null) {
                return errorResult(
                    "BinaryExporter.export(File, DomainObject, AddressSetView, TaskMonitor) not found");
            }

            File outputFile = new File(outputPath);
            TaskMonitor mon = monitor;
            exportMethod.invoke(exporter, outputFile, currentProgram, null, mon);

            JsonObject result = new JsonObject();
            result.addProperty("status", "exported");
            result.addProperty("output", outputPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to export binary: " + e.getMessage());
        }
    }

    // --- Disasm Handler ---

    private JsonObject handleDisasm(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        int count = getArgInt(args, "count", 10);

        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            // Use resolveAddress which handles 0x prefix and symbol lookup
            Address addr = resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            Instruction instruction = listing.getInstructionAt(addr);

            // If no instruction at exact address, try containing instruction (mid-instruction)
            if (instruction == null) {
                instruction = listing.getInstructionContaining(addr);
            }

            // If still null, try starting from containing function's entry point
            if (instruction == null) {
                Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    instruction = listing.getInstructionAt(func.getEntryPoint());
                }
            }

            if (instruction == null) {
                return errorResult("No instruction at address " + addressStr +
                    ". Address may be data or unanalyzed code.");
            }

            JsonArray results = new JsonArray();
            Instruction current = instruction;

            for (int i = 0; i < count && current != null; i++) {
                results.add(instructionToJson(current));
                current = current.getNext();
            }

            JsonObject result = new JsonObject();
            result.add("instructions", results);
            result.addProperty("count", results.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble: " + e.getMessage());
        }
    }

    private JsonObject instructionToJson(Instruction instr) throws MemoryAccessException {
        byte[] byteArray = instr.getBytes();
        StringBuilder bytesHex = new StringBuilder();
        for (byte b : byteArray) {
            bytesHex.append(String.format("%02x", b & 0xff));
        }

        JsonArray operands = new JsonArray();
        int numOperands = instr.getNumOperands();
        for (int j = 0; j < numOperands; j++) {
            operands.add(new JsonPrimitive(instr.getDefaultOperandRepresentation(j)));
        }

        JsonObject instrData = new JsonObject();
        instrData.addProperty("address", instr.getAddress().toString());
        instrData.addProperty("bytes", bytesHex.toString());
        instrData.addProperty("mnemonic", instr.getMnemonicString());
        instrData.add("operands", operands);
        return instrData;
    }

    /**
     * Disassemble at ADDRESS if no instruction is there yet (auto-analysis
     * often never reaches computed-jump targets / inline-table resume
     * addresses), then report whether an instruction actually landed there --
     * disassemble() can return false, or even true while the target still has
     * no instruction, with no exception either way.
     */
    private JsonObject handleDisasmAt(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addressStr = getArgString(args, "address");
        int count = getArgInt(args, "count", 1);
        if (addressStr == null || addressStr.isEmpty()) {
            return errorResult("Address required");
        }

        try {
            Address addr = resolveAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            boolean alreadyPresent = listing.getInstructionAt(addr) != null;
            boolean ok = alreadyPresent;

            int txId = currentProgram.startTransaction("Disassemble at address");
            try {
                if (!alreadyPresent) {
                    ok = disassemble(addr);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }

            boolean landed = listing.getInstructionAt(addr) != null;

            JsonObject result = new JsonObject();
            result.addProperty("address", addr.toString());
            result.addProperty("already_disassembled", alreadyPresent);
            result.addProperty("ok", ok);
            result.addProperty("landed", landed);
            result.addProperty("status", landed ? "disassembled" : "failed");

            if (landed) {
                JsonArray instrs = new JsonArray();
                Instruction current = listing.getInstructionAt(addr);
                for (int i = 0; i < count && current != null; i++) {
                    instrs.add(instructionToJson(current));
                    current = current.getNext();
                }
                result.add("instructions", instrs);
            } else {
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (owner != null) {
                    result.addProperty("hint", "Address falls inside existing function "
                        + owner.getName() + "@" + owner.getEntryPoint()
                        + "; stale/overlapping instructions may be blocking disassembly. Try `ghidra clear` first.");
                }
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to disassemble at " + addressStr + ": " + e.getMessage());
        }
    }

    /**
     * Clear all code units overlapping [start, end] (retroactively undoing
     * auto-analysis that linearly disassembled through inline data), optionally
     * re-disassembling at a precise address in the same call.
     */
    private JsonObject handleClearRange(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String startStr = getArgString(args, "start");
        String endStr = getArgString(args, "end");
        String disasmAtStr = getArgString(args, "disasm_at");
        if (startStr == null || endStr == null) {
            return errorResult("start and end addresses required");
        }

        try {
            Address start = resolveAddress(startStr);
            if (start == null) return errorResult("Invalid start address: " + startStr);
            Address end = resolveAddress(endStr);
            if (end == null) return errorResult("Invalid end address: " + endStr);

            Address disasmAt = null;
            if (disasmAtStr != null && !disasmAtStr.isEmpty()) {
                disasmAt = resolveAddress(disasmAtStr);
                if (disasmAt == null) return errorResult("Invalid disasm_at address: " + disasmAtStr);
            }

            JsonObject result = new JsonObject();
            int txId = currentProgram.startTransaction("Clear code units");
            try {
                clearListing(start, end);
                result.addProperty("status", "cleared");
                result.addProperty("start", start.toString());
                result.addProperty("end", end.toString());

                if (disasmAt != null) {
                    boolean ok = disassemble(disasmAt);
                    boolean landed = currentProgram.getListing().getInstructionAt(disasmAt) != null;
                    result.addProperty("disasm_at", disasmAt.toString());
                    result.addProperty("ok", ok);
                    result.addProperty("landed", landed);
                    result.addProperty("status", (ok && landed) ? "cleared_and_disassembled" : "cleared_disasm_incomplete");
                    if (!landed) {
                        result.addProperty("hint", "clearEnd may need to extend further past disasm_at: "
                            + "disassemble() can silently land no instruction if the new instruction's "
                            + "tail bytes would still overlap a stale code unit outside the cleared range.");
                    }
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, true);
                throw e;
            }
            return result;
        } catch (Exception e) {
            return errorResult("Failed to clear range: " + e.getMessage());
        }
    }

    // --- Stats Handler ---

    private JsonObject handleStats() {
        if (currentProgram == null) return errorResult("No program loaded");

        try {
            FunctionManager fm = currentProgram.getFunctionManager();
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            Memory memory = currentProgram.getMemory();
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            Listing listing = currentProgram.getListing();

            int functionCount = fm.getFunctionCount();

            int symbolCount = 0;
            SymbolIterator symIter = symbolTable.getAllSymbols(true);
            while (symIter.hasNext()) { symIter.next(); symbolCount++; }

            int stringCount = 0;
            DataIterator dataIter = listing.getDefinedData(true);
            while (dataIter.hasNext()) {
                if (dataIter.next().hasStringValue()) stringCount++;
            }

            long memorySize = 0;
            int sectionCount = 0;
            for (MemoryBlock block : memory.getBlocks()) {
                memorySize += block.getSize();
                sectionCount++;
            }

            int importCount = 0;
            SymbolIterator extSyms = symbolTable.getExternalSymbols();
            while (extSyms.hasNext()) { extSyms.next(); importCount++; }

            int exportCount = 0;
            ghidra.program.model.address.AddressIterator epIter = symbolTable.getExternalEntryPointIterator();
            while (epIter.hasNext()) { epIter.next(); exportCount++; }

            int dataTypeCount = dtm.getDataTypeCount(false);

            int instructionCount = 0;
            InstructionIterator instrIter = listing.getInstructions(true);
            while (instrIter.hasNext()) { instrIter.next(); instructionCount++; }

            JsonObject stats = new JsonObject();
            stats.addProperty("functions", functionCount);
            stats.addProperty("symbols", symbolCount);
            stats.addProperty("strings", stringCount);
            stats.addProperty("imports", importCount);
            stats.addProperty("exports", exportCount);
            stats.addProperty("memory_size", memorySize);
            stats.addProperty("sections", sectionCount);
            stats.addProperty("data_types", dataTypeCount);
            stats.addProperty("instructions", instructionCount);
            stats.addProperty("program_name", currentProgram.getName());
            stats.addProperty("executable_format", currentProgram.getExecutableFormat());
            String compiler = currentProgram.getCompiler();
            stats.addProperty("compiler", (compiler != null && !compiler.isEmpty()) ? compiler : "Unknown");

            JsonObject result = new JsonObject();
            result.add("stats", stats);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to gather statistics: " + e.getMessage());
        }
    }

    // --- Script Handlers ---

    private JsonObject handleScriptRun(JsonObject args) {
        String scriptPath = getArgString(args, "path");
        String inlineSource = getArgString(args, "source");
        if ((scriptPath == null || scriptPath.isEmpty()) && (inlineSource == null || inlineSource.isEmpty())) {
            return errorResult("Script path or inline source required");
        }

        File scriptFile;
        File tempDir = null;
        if (inlineSource != null && !inlineSource.isEmpty()) {
            // Stdin-sourced one-offs (`ghidra script run -`): stage the source into a
            // temp file and run it through the exact same compile/execute path as a
            // file on disk, rather than eval'ing it directly -- this is what keeps
            // inline snippets going through Ghidra's normal script bundle/compile gate
            // instead of adding a second, less-sandboxed execution path.
            Matcher classMatch = Pattern.compile("public\\s+class\\s+(\\w+)").matcher(inlineSource);
            if (!classMatch.find()) {
                return errorResult("Inline script source must define `public class <Name> extends GhidraScript`");
            }
            String className = classMatch.group(1);
            try {
                tempDir = java.nio.file.Files.createTempDirectory("ghidra-cli-stdin-script").toFile();
                scriptFile = new File(tempDir, className + ".java");
                try (FileWriter fw = new FileWriter(scriptFile)) {
                    fw.write(inlineSource);
                }
            } catch (IOException e) {
                return errorResult("Failed to stage inline script: " + e.getMessage());
            }
        } else {
            // Resolve to an absolute path so the script is found regardless of the
            // working directory the bridge JVM inherited. This removes the RE-repo
            // workaround of copying scripts into a global scripts directory.
            scriptFile = new File(scriptPath).getAbsoluteFile();
            if (!scriptFile.exists()) return errorResult("Script not found: " + scriptFile.getPath());
        }
        final File cleanupTempDir = tempDir;

        String[] scriptArgs = getArgStringArray(args, "args");
        ResourceFile source = new ResourceFile(scriptFile);
        ResourceFile sourceDir = source.getParentFile();

        StringWriter buffer = new StringWriter();
        PrintWriter out = new PrintWriter(buffer);
        try {
            // A script only resolves if its parent directory is a registered
            // bundle/source directory. Register it if it is not already.
            //
            // Done via reflection on purpose: referencing BundleHost/GhidraBundle
            // directly -- even Class.forName() with a literal class-name string --
            // makes bnd's OSGi Import-Package analysis add ghidra.app.plugin.core.osgi
            // as a hard dependency of the bridge's own bundle, which the bridge
            // cannot wire, so the whole bridge fails to load. Every reflective type
            // token below is obtained via .getClass() on an already-held instance
            // instead, exactly like the getBundleHost()/bhClass pair here already
            // did. handleScriptList() uses the same .getClass() pattern.
            Object bundleHost = GhidraScriptUtil.class
                .getMethod("getBundleHost").invoke(null);
            if (bundleHost == null) return errorResult("Ghidra script bundle host unavailable");
            Class<?> bhClass = bundleHost.getClass();
            // getGhidraBundle() is a plain map lookup; getExistingGhidraBundle()
            // is for callers who expect the bundle to already exist and logs an
            // ERROR to application.log on a miss -- which is exactly what happens
            // here on every first-ever run of a script in a new directory. Using
            // getGhidraBundle() for this existence check avoids that misleading
            // (and otherwise benign) log noise.
            Object bundle = bhClass
                .getMethod("getGhidraBundle", ResourceFile.class)
                .invoke(bundleHost, sourceDir);
            if (bundle == null) {
                // enabled=true: matches how Ghidra's own script manager registers
                // a directory a user actually wants to run scripts from.
                bundle = bhClass.getMethod("add", ResourceFile.class, boolean.class, boolean.class)
                    .invoke(bundleHost, sourceDir, true, true);
            }
            if (bundle == null) {
                return errorResult("Failed to register script bundle for " + sourceDir.getAbsolutePath());
            }

            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
            if (provider == null) {
                return errorResult("No script provider for " + scriptFile.getName()
                    + " (unsupported script type)");
            }

            GhidraScript script;
            if (scriptFile.getName().endsWith(".java")) {
                // Build and load the class from the EXACT bundle we just resolved
                // above, rather than delegating to provider.getScriptInstance(),
                // which internally re-resolves the bundle via
                // GhidraScriptUtil.findSourceDirectoryContaining(). That lookup
                // returns the FIRST registered source directory that is an
                // ancestor of the script -- not necessarily the most specific
                // one -- so when a broader, unrelated ancestor directory is also
                // registered as a bundle (e.g. from a prior `script run`/`script
                // list` against a sibling or parent project), it can silently
                // resolve to the WRONG bundle: either failing outright with
                // "Failed to get OSGi bundle containing script" because the
                // class isn't there, or worse, loading a same-named class from
                // the wrong bundle entirely. Pinning to `bundle` here sidesteps
                // that ambiguity altogether.
                Class<?> bundleClass = bundle.getClass();
                try {
                    bundleClass.getMethod("build", PrintWriter.class).invoke(bundle, out);
                    String locationId = (String) bundleClass
                        .getMethod("getLocationIdentifier").invoke(bundle);
                    bhClass.getMethod("activateSynchronously", String.class)
                        .invoke(bundleHost, locationId);
                } catch (java.lang.reflect.InvocationTargetException ite) {
                    Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
                    out.flush();
                    return errorResult("Script failed to build: " + cause.getMessage()
                        + (buffer.getBuffer().length() > 0 ? "\n" + buffer : ""));
                }

                // Typed as the org.osgi.framework.Bundle interface (not the
                // concrete Felix impl class .getOSGiBundle() actually returns):
                // reflectively invoking loadClass() via the concrete class's own
                // Method object throws IllegalAccessException, because that
                // class isn't public even though the method is -- the standard
                // reflection gotcha for "public method of non-public class".
                // Going through the public Bundle interface sidesteps it.
                Object rawOsgiBundle = bundleClass.getMethod("getOSGiBundle").invoke(bundle);
                if (rawOsgiBundle == null) {
                    out.flush();
                    return errorResult("Failed to get OSGi bundle containing script: "
                        + scriptFile.getPath()
                        + (buffer.getBuffer().length() > 0 ? "\n" + buffer : ""));
                }
                Bundle osgiBundle = (Bundle) rawOsgiBundle;
                String className = (String) bundleClass
                    .getMethod("classNameForScript", ResourceFile.class)
                    .invoke(bundle, source);
                Class<?> loadedClass;
                try {
                    loadedClass = osgiBundle.loadClass(className);
                } catch (ClassNotFoundException cnfe) {
                    return errorResult("The class could not be found. It must be the public "
                        + "class of the .java file: " + cnfe.getMessage());
                }
                if (!GhidraScript.class.isAssignableFrom(loadedClass)) {
                    return errorResult("Loaded class " + className + " does not extend GhidraScript");
                }
                script = (GhidraScript) loadedClass.getDeclaredConstructor().newInstance();
                script.setSourceFile(source);
            } else {
                // Non-Java providers (e.g. Python) aren't resolved via the OSGi
                // bundle path above; fall back to the provider's own resolution.
                script = provider.getScriptInstance(source, out);
            }
            script.setScriptArgs(scriptArgs);

            // Run on the program executor's exclusive objects. `monitor` is the
            // per-job cancellable JobTaskMonitor installed in executeProgramJob,
            // so cancel/status work for scripts with no extra machinery.
            //
            // Use the copy constructor rather than the 6-arg form: it only
            // references ghidra.app.script, avoiding OSGi Import-Package entries
            // on ghidra.framework.plugintool / ghidra.program.util that the bridge
            // bundle may not be able to wire.
            if (state == null) return errorResult("Bridge script state unavailable");
            GhidraState scriptState = new GhidraState(state);
            scriptState.setCurrentProgram(currentProgram);
            script.execute(scriptState, monitor, out);
            out.flush();

            JsonObject result = new JsonObject();
            result.addProperty("script", scriptFile.getName());
            result.addProperty("path", scriptFile.getAbsolutePath());
            result.addProperty("stdout", buffer.toString());
            result.add("args", toJsonArray(scriptArgs));

            // Artifact contract: validate declared outputs and fail closed on a
            // missing/empty/under-count artifact, so callers can trust the job
            // succeeded only when its expected records actually exist.
            return validateArtifacts(result, args, buffer.toString());
        } catch (GhidraScriptLoadException e) {
            return errorResult("Script failed to compile: " + e.getMessage());
        } catch (CancelledException e) {
            return errorResult("Script cancelled");
        } catch (Exception e) {
            // Preserve any output the script produced before it threw.
            out.flush();
            JsonObject err = errorResult("Script threw: " + e.getMessage());
            err.addProperty("stdout", buffer.toString());
            return err;
        } finally {
            if (cleanupTempDir != null) {
                scriptFile.delete();
                cleanupTempDir.delete();
            }
        }
    }

    /**
     * Validate the caller's declared output artifacts (the "expect" array) and
     * attach a manifest for each. A missing artifact, an empty one (unless
     * allow_empty), or one below its min_rows fails the whole job.
     */
    private JsonObject validateArtifacts(JsonObject result, JsonObject args, String stdout) {
        if (args == null || !args.has("expect") || !args.get("expect").isJsonArray()) {
            return result;
        }
        JsonArray expect = args.getAsJsonArray("expect");
        if (expect.size() == 0) return result;

        boolean allowEmpty = getArgBool(args, "allow_empty", false);
        JsonArray artifacts = new JsonArray();
        List<String> failures = new ArrayList<>();

        for (JsonElement el : expect) {
            if (!el.isJsonObject()) continue;
            JsonObject spec = el.getAsJsonObject();
            String path = getArgString(spec, "path");
            if (path == null) {
                failures.add("expected artifact with no path");
                continue;
            }
            String schema = getArgString(spec, "schema");
            JsonObject manifest = buildArtifactManifest(path, schema);
            artifacts.add(manifest);

            if (!manifest.get("exists").getAsBoolean()) {
                failures.add("missing: " + manifest.get("path").getAsString());
                continue;
            }
            if (manifest.get("bytes").getAsLong() == 0 && !allowEmpty) {
                failures.add("empty: " + manifest.get("path").getAsString());
            }
            if (spec.has("min_rows") && !spec.get("min_rows").isJsonNull()) {
                long minRows = spec.get("min_rows").getAsLong();
                if (!manifest.has("rows")) {
                    failures.add("min_rows set but " + manifest.get("path").getAsString()
                        + " is not a row-countable (.jsonl/.ndjson) artifact");
                } else if (manifest.get("rows").getAsLong() < minRows) {
                    failures.add(manifest.get("path").getAsString() + " has "
                        + manifest.get("rows").getAsLong() + " rows, expected >= " + minRows);
                }
            }
        }

        result.add("artifacts", artifacts);
        if (failures.isEmpty()) {
            return result;
        }
        JsonObject err = errorResult("Artifact validation failed: " + String.join("; ", failures));
        err.add("artifacts", artifacts);
        err.addProperty("stdout", stdout);
        return err;
    }

    /** Manifest for one output file: existence, size, row count, checksum, provenance. */
    private JsonObject buildArtifactManifest(String rawPath, String schema) {
        JsonObject m = new JsonObject();
        File f = new File(rawPath).getAbsoluteFile();
        m.addProperty("path", f.getAbsolutePath());
        if (schema != null) m.addProperty("schema", schema);
        if (!f.exists() || !f.isFile()) {
            m.addProperty("exists", false);
            return m;
        }
        m.addProperty("exists", true);
        m.addProperty("bytes", f.length());
        String lower = rawPath.toLowerCase();
        try {
            if (lower.endsWith(".jsonl") || lower.endsWith(".ndjson")) {
                m.addProperty("rows", countLines(f));
            }
            m.addProperty("sha256", sha256File(f));
        } catch (IOException e) {
            m.addProperty("manifest_error", e.getMessage());
        }
        if (currentProgram != null) {
            m.addProperty("program", currentProgram.getName());
            String binSha = currentProgram.getExecutableSHA256();
            if (binSha != null && !binSha.isEmpty()) m.addProperty("binary_sha256", binSha);
            m.addProperty("executable_format", currentProgram.getExecutableFormat());
        }
        String gv = ghidraVersion();
        if (!gv.isEmpty()) m.addProperty("ghidra_version", gv);
        return m;
    }

    /** Stream the file counting newlines; handles multi-GB JSONL exports. */
    private long countLines(File f) throws IOException {
        long count = 0;
        try (BufferedReader r = new BufferedReader(new FileReader(f))) {
            while (r.readLine() != null) count++;
        }
        return count;
    }

    /** Streaming SHA-256 so large artifacts are not fully buffered. */
    private String sha256File(File f) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
                int n;
                while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            }
            byte[] digest = md.digest();
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 unavailable", e);
        }
    }

    private volatile String cachedGhidraVersion;

    /** Ghidra application version via reflection (avoids an OSGi import on ghidra.framework). */
    private String ghidraVersion() {
        if (cachedGhidraVersion != null) return cachedGhidraVersion;
        try {
            Object v = Class.forName("ghidra.framework.Application")
                .getMethod("getApplicationVersion").invoke(null);
            cachedGhidraVersion = v == null ? "" : v.toString();
        } catch (Throwable t) {
            cachedGhidraVersion = "";
        }
        return cachedGhidraVersion;
    }

    private JsonObject handleScriptJava(JsonObject args) {
        return errorResult("Inline Java execution (`script java`) is disabled by design: every script, "
            + "including one-offs, is required to go through Ghidra's normal script bundle/compile gate "
            + "(GhidraScriptProvider.getScriptInstance) rather than a second, less-sandboxed eval path. "
            + "For a throwaway snippet without a checked-in file, use `ghidra script run -` and pipe the "
            + "Java source on stdin -- it is staged to a temp file and compiled through the same path.");
    }

    private JsonObject handleScriptPython(JsonObject args) {
        return errorResult("Python execution is not available: the Java bridge replaces the old Python "
            + "bridge.py entirely, and there is no embedded Python interpreter in this process. Port the "
            + "logic to a Java GhidraScript and use `ghidra script run PATH`, or `ghidra script run -` "
            + "for a one-off piped via stdin.");
    }

    private JsonObject handleScriptList() {
        try {
            JsonArray scripts = new JsonArray();

            // List scripts from Ghidra's script directories
            Class<?> utilClass = Class.forName("ghidra.app.script.GhidraScriptUtil");
            java.lang.reflect.Method getDirs = utilClass.getMethod("getScriptSourceDirectories");
            Object dirs = getDirs.invoke(null);

            if (dirs instanceof Iterable) {
                for (Object dirObj : (Iterable<?>) dirs) {
                    File dir = new File(dirObj.toString());
                    if (dir.exists() && dir.isDirectory()) {
                        for (File f : dir.listFiles()) {
                            if (f.getName().endsWith(".py") || f.getName().endsWith(".java")) {
                                JsonObject scriptObj = new JsonObject();
                                scriptObj.addProperty("name", f.getName());
                                scriptObj.addProperty("path", f.getAbsolutePath());
                                scriptObj.addProperty("type", f.getName().endsWith(".py") ? "python" : "java");
                                scripts.add(scriptObj);
                            }
                        }
                    }
                }
            }

            JsonObject result = new JsonObject();
            result.add("scripts", scripts);
            result.addProperty("count", scripts.size());
            return result;
        } catch (Exception e) {
            return errorResult("Failed to list scripts: " + e.getMessage());
        }
    }

    // --- Batch Handler ---

    private JsonObject handleBatch(JsonObject args) {
        // Batch operations are handled by the Rust side, not the bridge directly
        return errorResult("Batch operations are handled by the CLI, not via bridge script");
    }

    // --- Memory Read Handler ---

    private JsonObject handleReadMemory(JsonObject args) {
        String addrStr = getArgString(args, "address");
        if (addrStr == null) return errorResult("Address required");

        int size = 200;
        if (args != null && args.has("size")) {
            size = args.get("size").getAsInt();
        }

        try {
            ghidra.program.model.mem.Memory mem = currentProgram.getMemory();

            Address baseAddr = resolveAddress(addrStr);
            if (baseAddr == null) {
                return errorResult("Invalid address: " + addrStr);
            }

            // Read bytes
            byte[] bytes = new byte[size];
            int bytesRead = mem.getBytes(baseAddr, bytes);

            // Build hex string
            StringBuilder hexStr = new StringBuilder();
            for (int i = 0; i < bytesRead; i++) {
                hexStr.append(String.format("%02x", bytes[i] & 0xFF));
            }

            // Also interpret as array of 8-byte pointers
            JsonArray pointers = new JsonArray();
            for (int i = 0; i + 7 < bytesRead; i += 8) {
                long val = 0;
                for (int j = 0; j < 8; j++) {
                    val |= ((long)(bytes[i+j] & 0xFF)) << (8*j);
                }
                JsonObject ptrObj = new JsonObject();
                ptrObj.addProperty("offset", i);
                ptrObj.addProperty("address", baseAddr.add(i).toString());
                ptrObj.addProperty("value", String.format("0x%016x", val));

                // Check if value looks like a code address
                if (val >= 0x00401000L && val <= 0x05bb99ffL) {
                    ghidra.program.model.address.Address funcAddr =
                        currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(val);
                    ghidra.program.model.listing.Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
                    if (func != null) {
                        ptrObj.addProperty("function", func.getName());
                    }
                }

                pointers.add(ptrObj);
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", baseAddr.toString());
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
