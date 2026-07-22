// Integration-test fixture for the `ghidra script run` artifact contract.
// Writes `count` JSONL records to the path given as the first argument.
// Args: <output_path> <count>
// @category Test
import ghidra.app.script.GhidraScript;
import java.io.FileWriter;
import java.io.PrintWriter;

public class WriteArtifact extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        String outPath = scriptArgs[0];
        int count = Integer.parseInt(scriptArgs[1]);
        try (PrintWriter w = new PrintWriter(new FileWriter(outPath))) {
            for (int i = 0; i < count; i++) {
                w.println("{\"i\":" + i + "}");
            }
        }
        println("wrote " + count + " records to " + outPath);
    }
}
