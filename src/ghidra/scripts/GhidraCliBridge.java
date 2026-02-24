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
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Iterator;

public class GhidraCliBridge extends GhidraScript {

    private Gson gson = new GsonBuilder().serializeNulls().create();
    private long startTime;
    private static final Pattern NAMED_HEX_ADDRESS_PATTERN =
        Pattern.compile("(?i)^(?:FUN|SUB|LAB|DAT)_([0-9a-f]+)$");

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

        // Bind to dynamic port on localhost only
        ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        int port = serverSocket.getLocalPort();

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

        // Accept loop
        boolean running = true;
        while (running) {
            try {
                Socket client = serverSocket.accept();
                try (
                    BufferedReader in = new BufferedReader(new InputStreamReader(client.getInputStream()));
                    PrintWriter out = new PrintWriter(new OutputStreamWriter(client.getOutputStream()), true)
                ) {
                    String line;
                    while ((line = in.readLine()) != null) {
                        line = line.trim();
                        if (line.isEmpty()) continue;

                        HandleResult result = handleRequest(line);
                        out.println(gson.toJson(result.response));
                        out.flush();

                        if (result.shouldShutdown) {
                            running = false;
                            break;
                        }
                    }
                } catch (IOException e) {
                    printerr("Client error: " + e.getMessage());
                } finally {
                    client.close();
                }
            } catch (IOException e) {
                if (running) {
                    printerr("Accept error: " + e.getMessage());
                }
            }
        }

        // Cleanup: close the server socket but leave port/pid files for the
        // Rust CLI to clean up. Deleting them here creates a race: the JVM is
        // still unwinding (closing the Ghidra project, releasing locks) but
        // stop_bridge() can no longer find the PID to wait on, so it returns
        // early while the project lock is still held.
        serverSocket.close();
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

    private HandleResult handleRequest(String line) {
        try {
            JsonObject req = JsonParser.parseString(line).getAsJsonObject();
            String command = req.has("command") ? req.get("command").getAsString() : null;
            JsonObject args = req.has("args") && !req.get("args").isJsonNull()
                ? req.getAsJsonObject("args") : new JsonObject();

            if ("shutdown".equals(command)) {
                JsonObject resp = new JsonObject();
                resp.addProperty("status", "shutdown");
                return new HandleResult(resp, true);
            }

            JsonObject result = dispatchCommand(command, args);
            if (result == null) {
                return new HandleResult(errorResponse("Unknown command: " + command), false);
            }

            // Check if the handler returned an error
            if (result.has("error")) {
                return new HandleResult(errorResponse(result.get("error").getAsString()), false);
            }

            return new HandleResult(successResponse(result), false);

        } catch (Exception e) {
            return new HandleResult(errorResponse(e.getMessage()), false);
        }
    }

    private JsonObject dispatchCommand(String command, JsonObject args) {
        if (command == null) return null;
        switch (command) {
            case "ping":            return handlePing();
            case "program_info":    return handleProgramInfo();
            case "decompile":       return handleDecompile(args);
            case "list_strings":    return handleListStrings(args);
            case "list_imports":    return handleListImports();
            case "list_exports":    return handleListExports();
            case "memory_map":      return handleMemoryMap();
            case "xrefs_to":        return handleXrefsTo(args);
            case "xrefs_from":      return handleXrefsFrom(args);
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
            // Function commands
            case "function_list":   return handleFunctionList(args);
            case "function_get":    return handleFunctionGet(args);
            case "function_create": return handleFunctionCreate(args);
            case "function_delete": return handleFunctionDelete(args);
            case "function_set_signature": return handleFunctionSetSignature(args);
            // Type commands
            case "type_list":       return handleTypeList(args);
            case "type_get":        return handleTypeGet(args);
            case "type_create":     return handleTypeCreate(args);
            case "type_apply":      return handleTypeApply(args);
            case "type_import_c":   return handleTypeImportC(args);
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
            case "stats":           return handleStats();
            // Script commands
            case "script_run":      return handleScriptRun(args);
            case "script_java":     return handleScriptJava(args);
            case "script_python":   return handleScriptPython(args);
            case "script_list":     return handleScriptList();
            // Batch
            case "batch":           return handleBatch(args);
            // Bridge info
            case "bridge_info":     return handleBridgeInfo();
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
        JsonObject resp = new JsonObject();
        resp.addProperty("status", "error");
        resp.addProperty("message", message);
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

    // --- Command Handlers (M1: Core) ---

    private JsonObject handlePing() {
        JsonObject result = new JsonObject();
        result.addProperty("message", "pong");
        return result;
    }

    private JsonObject handleBridgeInfo() {
        JsonObject result = new JsonObject();
        result.addProperty("has_current_program", currentProgram != null);
        if (currentProgram != null) {
            result.addProperty("current_program", currentProgram.getName());
        }
        result.addProperty("uptime_ms", System.currentTimeMillis() - startTime);

        Project project = state.getProject();
        if (project != null) {
            result.addProperty("project_name", project.getName());
            try {
                ProjectData projectData = project.getProjectData();
                DomainFolder rootFolder = projectData.getRootFolder();
                result.addProperty("program_count", rootFolder.getFiles().length);
            } catch (Exception e) {
                result.addProperty("program_count", 0);
            }
        }
        return result;
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

    private JsonObject handleFunctionList(JsonObject args) {
        if (currentProgram == null) {
            return errorResult("No program loaded");
        }

        int limit = getArgInt(args, "limit", 0);
        String nameFilter = getArgString(args, "filter");

        JsonArray functions = new JsonArray();
        FunctionManager fm = currentProgram.getFunctionManager();
        int count = 0;

        FunctionIterator iter = fm.getFunctions(true);
        while (iter.hasNext()) {
            if (limit > 0 && count >= limit) break;

            Function func = iter.next();
            String name = func.getName();

            if (nameFilter != null && !name.toLowerCase().contains(nameFilter.toLowerCase())) {
                continue;
            }

            JsonObject funcData = new JsonObject();
            funcData.addProperty("name", name);
            funcData.addProperty("address", func.getEntryPoint().toString());
            funcData.addProperty("size", func.getBody().getNumAddresses());
            funcData.addProperty("entry_point", func.getEntryPoint().toString());

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

            String comment = func.getComment();
            if (comment != null) {
                funcData.addProperty("comment", comment);
            } else {
                funcData.add("comment", JsonNull.INSTANCE);
            }

            functions.add(funcData);
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

    private JsonObject handleFunctionGet(JsonObject args) {
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

    private JsonObject handleFunctionCreate(JsonObject args) {
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
            if (fm.getFunctionContaining(addr) != null) {
                return errorResult("Function already exists at " + addr.toString());
            }

            String functionName = (requestedName == null || requestedName.isEmpty())
                ? ("FUN_" + addr.toString().replace(":", ""))
                : requestedName;

            int txId = currentProgram.startTransaction("Create function");
            try {
                Function created = fm.createFunction(functionName, addr, null, SourceType.USER_DEFINED);
                if (created == null) {
                    currentProgram.endTransaction(txId, false);
                    return errorResult("Failed to create function at " + addr.toString());
                }
                currentProgram.endTransaction(txId, true);

                JsonObject result = new JsonObject();
                result.addProperty("status", "created");
                result.addProperty("name", created.getName());
                result.addProperty("address", created.getEntryPoint().toString());
                return result;
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }
        } catch (Exception e) {
            return errorResult("Failed to create function: " + e.getMessage());
        }
    }

    private JsonObject handleFunctionDelete(JsonObject args) {
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
                currentProgram.endTransaction(txId, false);
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

            TaskMonitor mon = new ConsoleTaskMonitor();
            DecompileResults results = decompiler.decompileFunction(func, 30, mon);

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
                return result;
            } else {
                return errorResult("Decompilation failed");
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
            TaskMonitor mon = new ConsoleTaskMonitor();
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
            TaskMonitor mon = new ConsoleTaskMonitor();

            // Use GhidraScript's built-in analyzeAll which works across Ghidra versions
            analyzeAll(currentProgram);

            // Save the program
            try {
                currentProgram.save("Analysis complete", mon);
            } catch (Exception saveErr) {
                // Best effort
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
            TaskMonitor mon = new ConsoleTaskMonitor();

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
            return errorResult("Unsupported export format: " + exportFormat);
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
            // analyzer didn't classify as string data types (common on PE binaries).
            if (results.size() == 0 && !pattern.isEmpty()) {
                Memory memory = currentProgram.getMemory();
                byte[] searchBytes = pattern.getBytes(java.nio.charset.StandardCharsets.UTF_8);

                Address addr = memory.getMinAddress();
                while (addr != null && results.size() < 100) {
                    Address found = memory.findBytes(addr, searchBytes, null, true, monitor);
                    if (found == null) break;

                    // Try to extract the full null-terminated string at this address
                    String extracted = extractStringAt(memory, found, 4096);
                    if (extracted != null && !extracted.isEmpty()) {
                        JsonObject item = new JsonObject();
                        item.addProperty("address", found.toString());
                        item.addProperty("value", extracted);
                        item.addProperty("length", extracted.length());
                        results.add(item);
                    }

                    addr = found.add(Math.max(1, extracted != null ? extracted.length() : 1));
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
                currentProgram.endTransaction(txId, false);
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

    private JsonObject handleSymbolDelete(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "name");
        if (target == null) return errorResult("Symbol target required");

        try {
            Symbol symbol = findUniqueSymbolByNameOrAddress(target);
            Address symbolAddr = symbol.getAddress();
            String deletedName = symbol.getName(true);

            int txId = currentProgram.startTransaction("Delete symbol");
            try {
                symbol.delete();
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "deleted");
            result.addProperty("name", deletedName);
            if (symbolAddr != null) {
                result.addProperty("address", symbolAddr.toString());
            } else {
                result.add("address", JsonNull.INSTANCE);
            }
            return result;
        } catch (IllegalArgumentException e) {
            return errorResult(e.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to delete symbol: " + e.getMessage());
        }
    }

    private JsonObject handleSymbolRename(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String target = getArgString(args, "address");
        String newName = getArgString(args, "new_name");
        if (target == null) return errorResult("Symbol target required");
        if (newName == null || newName.trim().isEmpty()) {
            return errorResult("New name required");
        }

        // Check for explicit --namespace arg (may be null = not provided, or "" = global)
        String namespaceArg = getArgString(args, "namespace");

        try {
            Symbol symbol = findUniqueSymbolByNameOrAddress(target);
            Address symbolAddr = symbol.getAddress();
            if (symbolAddr == null) {
                return errorResult("Symbol has no address: " + target);
            }

            String oldName = symbol.getName(true); // include namespace
            String simpleName = newName;
            String namespacePath = null;

            // Determine namespace: --namespace flag takes precedence over :: parsing
            if (namespaceArg != null) {
                // Explicit namespace provided (empty string = global namespace)
                namespacePath = namespaceArg;
                // If new_name also has ::, extract just the simple name
                int lastColon = newName.lastIndexOf("::");
                if (lastColon >= 0) {
                    simpleName = newName.substring(lastColon + 2);
                }
            } else {
                // Parse :: from new_name
                int lastColon = newName.lastIndexOf("::");
                if (lastColon >= 0) {
                    namespacePath = newName.substring(0, lastColon);
                    simpleName = newName.substring(lastColon + 2);
                }
            }

            int txId = currentProgram.startTransaction("Rename symbol");
            try {
                if (namespacePath != null) {
                    Namespace ns = createNamespaceHierarchy(namespacePath);
                    symbol.setNameAndNamespace(
                        simpleName, ns, SourceType.USER_DEFINED);
                } else {
                    symbol.setName(simpleName, SourceType.USER_DEFINED);
                }
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "renamed");
            result.addProperty("address", symbolAddr.toString());
            result.addProperty("old_name", oldName);
            result.addProperty("new_name", symbol.getName(true));
            result.addProperty("namespace", symbol.getParentNamespace().getName(true));
            result.addProperty("type", symbol.getSymbolType().toString());
            return result;
        } catch (IllegalArgumentException e) {
            return errorResult(e.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to rename: " + e.getMessage());
        }
    }

    /**
     * Create a namespace hierarchy from a "::" separated path.
     * E.g., "A" creates a single namespace,
     * "A::B::C" creates A -> B -> C hierarchy.
     * Empty/null path returns the global namespace.
     */
    private Namespace createNamespaceHierarchy(String path) throws Exception {
        if (path == null || path.isEmpty()) {
            return currentProgram.getGlobalNamespace();
        }
        SymbolTable symbolTable = currentProgram.getSymbolTable();
        String[] parts = path.split("::");
        Namespace parent = currentProgram.getGlobalNamespace();

        for (String part : parts) {
            part = part.trim();
            if (part.isEmpty()) continue;
            Namespace existing = symbolTable.getNamespace(part, parent);
            if (existing != null) {
                parent = existing;
            } else {
                parent = symbolTable.createNameSpace(parent, part, SourceType.USER_DEFINED);
            }
        }
        return parent;
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

        DataTypeManager dtm = currentProgram.getDataTypeManager();

        // Try by path first, then by name
        DataType dataType = dtm.getDataType(typeName);
        if (dataType == null) {
            Iterator<DataType> dtIter = dtm.getAllDataTypes();
            while (dtIter.hasNext()) {
                DataType dt = dtIter.next();
                if (dt.getName().equals(typeName)) {
                    dataType = dt;
                    break;
                }
            }
        }

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
        }

        return typeInfo;
    }

    private JsonObject handleTypeCreate(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String typeName = getArgString(args, "definition");
        if (typeName == null) typeName = getArgString(args, "name");
        if (typeName == null) return errorResult("Type name required");

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            int txId = currentProgram.startTransaction("Create type");
            try {
                StructureDataType newStruct = new StructureDataType(typeName, 0);
                dtm.addDataType(newStruct, null);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
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
        if (addressStr == null || typeName == null) {
            return errorResult("Address and type_name required");
        }

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            DataTypeManager dtm = currentProgram.getDataTypeManager();
            DataType dataType = dtm.getDataType(typeName);
            if (dataType == null) {
                Iterator<DataType> dtIter = dtm.getAllDataTypes();
                while (dtIter.hasNext()) {
                    DataType dt = dtIter.next();
                    if (dt.getName().equals(typeName)) {
                        dataType = dt;
                        break;
                    }
                }
            }
            if (dataType == null) {
                return errorResult("Type not found: " + typeName);
            }

            int txId = currentProgram.startTransaction("Apply type");
            try {
                Listing listing = currentProgram.getListing();
                listing.createData(addr, dataType);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "applied");
            result.addProperty("address", addressStr);
            result.addProperty("type", typeName);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to apply type: " + e.getMessage());
        }
    }

    // --- Import C Types Handler ---

    private JsonObject handleTypeImportC(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String code = getArgString(args, "code");
        if (code == null || code.trim().isEmpty()) {
            return errorResult("C code required");
        }

        String categoryPath = getArgString(args, "category");

        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();

            // Ensure trailing semicolon for CParser
            String processedCode = code.trim();
            if (!processedCode.endsWith(";")) {
                processedCode += ";";
            }

            int txId = currentProgram.startTransaction("Import C types");
            try {
                // Parse into program DTM
                CParser parser = new CParser(dtm, true,
                    new DataTypeManager[] { dtm });
                parser.parse(processedCode);
                String parseMessages = parser.getParseMessages();

                // Collect all explicitly defined type names from the parser
                Set<String> definedNames = new HashSet<>();
                definedNames.addAll(parser.getComposites().keySet());
                definedNames.addAll(parser.getEnums().keySet());
                definedNames.addAll(parser.getTypes().keySet());
                definedNames.addAll(parser.getFunctions().keySet());
                Set<DataType> parsedTypes = new HashSet<>();
                parsedTypes.addAll(parser.getComposites().values());
                parsedTypes.addAll(parser.getEnums().values());
                parsedTypes.addAll(parser.getTypes().values());
                parsedTypes.addAll(parser.getFunctions().values());

                // If --category specified, move defined types to target category
                CategoryPath lookupPath = CategoryPath.ROOT;
                if (categoryPath != null) {
                    String normalizedPath = categoryPath.startsWith("/")
                        ? categoryPath : "/" + categoryPath;
                    CategoryPath targetPath = new CategoryPath(normalizedPath);
                    Category targetCat = dtm.createCategory(targetPath);

                    // Move only datatypes touched by this parse operation.
                    for (DataType dt : parsedTypes) {
                        if (!isUserFacingDataType(dt)) continue;
                        if (dt.getCategoryPath().equals(targetPath)) continue;
                        targetCat.moveDataType(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                    }
                    lookupPath = targetPath;
                }

                currentProgram.endTransaction(txId, true);

                // Build response with all imported types
                JsonArray typesArray = new JsonArray();
                for (String name : definedNames) {
                    DataType best = findBestParsedDataType(name, parsedTypes, lookupPath);
                    if (best == null) {
                        best = findBestDataType(dtm, name, lookupPath);
                    }
                    if (best != null) {
                        JsonObject typeInfo = new JsonObject();
                        typeInfo.addProperty("name", best.getName());
                        typeInfo.addProperty("path", best.getPathName());
                        typeInfo.addProperty("size", best.getLength());
                        typeInfo.addProperty("category",
                            best.getCategoryPath().toString());
                        typesArray.add(typeInfo);
                    }
                }

                JsonObject response = new JsonObject();
                response.addProperty("status", "imported");
                response.add("types", typesArray);
                if (parseMessages != null && !parseMessages.trim().isEmpty()) {
                    response.addProperty("messages", parseMessages.trim());
                }
                return response;

            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

        } catch (ParseException pe) {
            return errorResult("C parse error: " + pe.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to import C types: " + e.getMessage());
        }
    }

    // --- Function Set Signature Handler ---

    private JsonObject handleFunctionSetSignature(JsonObject args) {
        if (currentProgram == null) return errorResult("No program loaded");

        String addrStr = getArgString(args, "address");
        String signature = getArgString(args, "signature");
        if (addrStr == null) return errorResult("Function address required");
        if (signature == null || signature.trim().isEmpty()) {
            return errorResult("Signature string required");
        }

        try {
            // Step 1: Resolve the function
            Address addr = resolveAddress(addrStr);
            if (addr == null) return errorResult("Cannot resolve address: " + addrStr);

            FunctionManager fm = currentProgram.getFunctionManager();
            Function func = fm.getFunctionAt(addr);
            if (func == null) {
                func = fm.getFunctionContaining(addr);
            }
            if (func == null) return errorResult("No function at address: " + addrStr);

            // Step 2: Pre-process the signature
            // CParser (C.jj:1194-1204) defines tokens for __cdecl, __stdcall, __fastcall,
            // __vectorcall, __rustcall, __pascal — but NOT __thiscall.
            // We mirror applyFunctionQualifiers() (C.jj:654-696): strip __thiscall from
            // the string and apply it separately via setCallingConvention().
            String processedSig = signature.trim();
            boolean isThiscall = false;
            if (processedSig.contains("__thiscall")) {
                isThiscall = true;
                processedSig = processedSig.replace("__thiscall", "").replaceAll("\\s+", " ").trim();
            }

            // Ensure trailing semicolon for CParser
            if (!processedSig.endsWith(";")) {
                processedSig += ";";
            }

            // Step 3: Parse with CParser
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            CParser parser = new CParser(dtm, false, new DataTypeManager[] { dtm });
            DataType parsed = parser.parse(processedSig);

            if (!(parsed instanceof FunctionDefinition)) {
                return errorResult("Could not parse as function signature: " + signature);
            }
            FunctionDefinition funcDef = (FunctionDefinition) parsed;

            // Step 4: Apply within a transaction
            int txId = currentProgram.startTransaction("Set function signature");
            try {
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    func.getEntryPoint(),
                    funcDef,
                    SourceType.USER_DEFINED,
                    false,  // don't preserve calling convention
                    false,  // applyEmptyComposites
                    DataTypeConflictHandler.REPLACE_HANDLER,
                    FunctionRenameOption.RENAME
                );
                boolean applied = cmd.applyTo(currentProgram);
                if (!applied) {
                    currentProgram.endTransaction(txId, false);
                    return errorResult("Failed to apply signature: " + cmd.getStatusMsg());
                }

                // Re-fetch function after signature change
                func = fm.getFunctionAt(func.getEntryPoint());

                // Set __thiscall calling convention (mirrors C.jj applyFunctionQualifiers())
                if (isThiscall && func != null) {
                    func.setCallingConvention("__thiscall");
                }

                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            // Build response
            func = fm.getFunctionAt(addr);
            JsonObject result = new JsonObject();
            result.addProperty("status", "updated");
            result.addProperty("address", addr.toString());
            if (func != null) {
                result.addProperty("name", func.getName());
                result.addProperty("namespace", func.getParentNamespace().getName(true));
                result.addProperty("calling_convention", func.getCallingConventionName());
                result.addProperty("signature", func.getPrototypeString(false, false));
                result.addProperty("parameter_count", func.getParameterCount());
            }
            return result;

        } catch (ParseException pe) {
            return errorResult("Signature parse error: " + pe.getMessage());
        } catch (Exception e) {
            return errorResult("Failed to set signature: " + e.getMessage());
        }
    }

    /**
     * Find all user-facing data types matching a name, excluding internal
     * /functions/ category types (FunctionDefinition internals).
     */
    private List<DataType> findUserDataTypes(DataTypeManager dtm, String name) {
        List<DataType> all = new ArrayList<>();
        dtm.findDataTypes(name, all);
        List<DataType> result = new ArrayList<>();
        for (DataType dt : all) {
            if (!dt.getName().equals(name)) continue;
            if (!isUserFacingDataType(dt)) continue;
            result.add(dt);
        }
        return result;
    }

    private boolean isUserFacingDataType(DataType dt) {
        if (dt == null) return false;
        return !dt.getCategoryPath().toString().equals("/functions");
    }

    private DataType findBestParsedDataType(String name, Set<DataType> parsed,
            CategoryPath preferred) {
        DataType best = null;
        for (DataType dt : parsed) {
            if (!isUserFacingDataType(dt)) continue;
            if (!dt.getName().equals(name)) continue;
            if (dt.getCategoryPath().equals(preferred)) {
                return dt;
            }
            if (best == null) {
                best = dt;
            }
        }
        return best;
    }

    /**
     * Find the best user-facing data type for a name, preferring the given
     * category path.
     */
    private DataType findBestDataType(DataTypeManager dtm, String name,
            CategoryPath preferred) {
        DataType best = null;
        for (DataType dt : findUserDataTypes(dtm, name)) {
            if (dt.getCategoryPath().equals(preferred)) {
                return dt; // exact match
            }
            if (best == null) {
                best = dt;
            }
        }
        return best;
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
                currentProgram.endTransaction(txId, false);
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
                currentProgram.endTransaction(txId, false);
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

            Reference[] refs = refMgr.getReferencesFrom(func.getEntryPoint());
            for (Reference ref : refs) {
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
            count++;
        }

        JsonObject result = new JsonObject();
        result.add("nodes", nodes);
        result.add("edges", edges);
        result.addProperty("node_count", nodes.size());
        result.addProperty("edge_count", edges.size());
        return result;
    }

    private Symbol findUniqueSymbolByNameOrAddress(String target) {
        if (currentProgram == null || target == null || target.isEmpty()) {
            throw new IllegalArgumentException("Symbol target required");
        }

        SymbolTable symbolTable = currentProgram.getSymbolTable();

        // Prefer exact name matches so non-primary labels are renamed correctly.
        List<Symbol> namedMatches = new ArrayList<>();
        SymbolIterator syms = symbolTable.getSymbols(target);
        while (syms.hasNext()) {
            Symbol s = syms.next();
            Address symAddr = s.getAddress();
            if (symAddr != null && !symAddr.isExternalAddress()) {
                namedMatches.add(s);
            }
        }

        if (namedMatches.size() == 1) {
            return namedMatches.get(0);
        }
        if (namedMatches.size() > 1) {
            throw new IllegalArgumentException(
                "Ambiguous symbol target '" + target + "' (" + namedMatches.size() +
                " matches). Use an address."
            );
        }

        Address addr = resolveAddress(target);
        if (addr == null) {
            throw new IllegalArgumentException("Symbol not found: " + target);
        }
        Symbol symbol = symbolTable.getPrimarySymbol(addr);
        if (symbol == null) {
            throw new IllegalArgumentException("No symbol at address: " + target);
        }
        return symbol;
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

        Reference[] refs = refMgr.getReferencesFrom(func.getEntryPoint());
        for (Reference ref : refs) {
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
                TaskMonitor mon = new ConsoleTaskMonitor();

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
            int txId = currentProgram.startTransaction("Patch bytes");
            try {
                memory.setBytes(addr, patchData);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
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

        try {
            Address addr = currentProgram.getAddressFactory().getAddress(addressStr);
            if (addr == null) return errorResult("Invalid address: " + addressStr);

            Listing listing = currentProgram.getListing();
            Instruction instruction = listing.getInstructionAt(addr);
            if (instruction == null) {
                return errorResult("No instruction at address: " + addressStr);
            }

            int instrLength = instruction.getLength();
            String processor = currentProgram.getLanguage().getProcessor().toString();

            byte nopByte;
            if (processor.toLowerCase().contains("x86")) {
                nopByte = (byte) 0x90;
            } else {
                nopByte = (byte) 0x00;
            }

            byte[] nopBytes = new byte[instrLength];
            Arrays.fill(nopBytes, nopByte);

            Memory memory = currentProgram.getMemory();
            int txId = currentProgram.startTransaction("NOP instruction");
            try {
                memory.setBytes(addr, nopBytes);
                currentProgram.endTransaction(txId, true);
            } catch (Exception e) {
                currentProgram.endTransaction(txId, false);
                throw e;
            }

            JsonObject result = new JsonObject();
            result.addProperty("status", "nopped");
            result.addProperty("address", addr.toString());
            result.addProperty("bytes", instrLength);
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
            // Use reflection to access BinaryExporter which may not always be available
            Class<?> exporterClass = Class.forName("ghidra.app.util.exporter.BinaryExporter");
            Object exporter = exporterClass.getDeclaredConstructor().newInstance();

            java.lang.reflect.Method exportMethod = exporterClass.getMethod("export",
                File.class, ghidra.program.model.listing.Program.class,
                ghidra.program.model.address.AddressSetView.class, TaskMonitor.class);

            File outputFile = new File(outputPath);
            TaskMonitor mon = new ConsoleTaskMonitor();
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
                Address instrAddr = current.getAddress();
                byte[] byteArray = current.getBytes();
                StringBuilder bytesHex = new StringBuilder();
                for (byte b : byteArray) {
                    bytesHex.append(String.format("%02x", b & 0xff));
                }

                String mnemonic = current.getMnemonicString();
                JsonArray operands = new JsonArray();
                int numOperands = current.getNumOperands();
                for (int j = 0; j < numOperands; j++) {
                    operands.add(new JsonPrimitive(current.getDefaultOperandRepresentation(j)));
                }

                JsonObject instrData = new JsonObject();
                instrData.addProperty("address", instrAddr.toString());
                instrData.addProperty("bytes", bytesHex.toString());
                instrData.addProperty("mnemonic", mnemonic);
                instrData.add("operands", operands);
                results.add(instrData);

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
        if (scriptPath == null) return errorResult("Script path required");

        try {
            File scriptFile = new File(scriptPath);
            if (!scriptFile.exists()) return errorResult("Script not found: " + scriptPath);

            // Use GhidraScript's runScript method
            runScript(scriptPath);

            JsonObject result = new JsonObject();
            result.addProperty("status", "executed");
            result.addProperty("script", scriptPath);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to run script: " + e.getMessage());
        }
    }

    private JsonObject handleScriptJava(JsonObject args) {
        return errorResult("Inline Java execution not supported in bridge mode");
    }

    private JsonObject handleScriptPython(JsonObject args) {
        return errorResult("Python execution not available (Java bridge replaces Python bridge)");
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
            ghidra.program.model.address.AddressFactory af = currentProgram.getAddressFactory();

            // Parse address
            long addrLong;
            if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
                addrLong = Long.parseUnsignedLong(addrStr.substring(2), 16);
            } else {
                addrLong = Long.parseUnsignedLong(addrStr, 16);
            }

            ghidra.program.model.address.Address baseAddr = af.getDefaultAddressSpace().getAddress(addrLong);

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
                ptrObj.addProperty("address", String.format("0x%08x", addrLong + i));
                ptrObj.addProperty("value", String.format("0x%016x", val));

                // Check if value looks like a code address
                if (val >= 0x00401000L && val <= 0x05bb99ffL) {
                    ghidra.program.model.address.Address funcAddr = af.getDefaultAddressSpace().getAddress(val);
                    ghidra.program.model.listing.Function func = currentProgram.getFunctionManager().getFunctionAt(funcAddr);
                    if (func != null) {
                        ptrObj.addProperty("function", func.getName());
                    }
                }

                pointers.add(ptrObj);
            }

            JsonObject result = new JsonObject();
            result.addProperty("address", String.format("0x%08x", addrLong));
            result.addProperty("size", bytesRead);
            result.addProperty("hex", hexStr.toString());
            result.add("pointers", pointers);
            return result;
        } catch (Exception e) {
            return errorResult("Failed to read memory: " + e.getMessage());
        }
    }
}
