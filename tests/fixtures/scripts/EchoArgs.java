// Integration-test fixture for `ghidra script run`.
// Echoes the positional arguments it receives so the test can prove that
// argument passing and stdout capture work end-to-end.
// @category Test
import ghidra.app.script.GhidraScript;

public class EchoArgs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] scriptArgs = getScriptArgs();
        println("ARGC=" + scriptArgs.length);
        for (int i = 0; i < scriptArgs.length; i++) {
            println("ARG" + i + "=" + scriptArgs[i]);
        }
    }
}
