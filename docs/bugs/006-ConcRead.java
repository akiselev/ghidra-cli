import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;
import java.util.*; import java.util.concurrent.*; import java.nio.file.*;
public class ConcRead extends GhidraScript {
  String work(Address a) throws Exception {
    Function f = currentProgram.getFunctionManager().getFunctionAt(a);
    StringBuilder sb = new StringBuilder(f.getName());
    for (Reference r : currentProgram.getReferenceManager().getReferencesTo(a)) sb.append(' ').append(r.getFromAddress());
    byte[] b = new byte[64]; currentProgram.getMemory().getBytes(a, b); sb.append(' ').append(Arrays.hashCode(b));
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    DecompileResults res = d.decompileFunction(f, 120, TaskMonitor.DUMMY);
    sb.append(' ').append(res.decompileCompleted() ? res.getDecompiledFunction().getC().hashCode() : -1);
    d.dispose(); return sb.toString();
  }
  public void run() throws Exception {
    List<Address> addrs = new ArrayList<>();
    for (String l : Files.readAllLines(Paths.get("/home/dev/projects/parasolid-re/work/haiku-trial/scope-imprint.tsv"))) {
      if (l.startsWith("address")) continue; addrs.add(toAddr("0x"+l.split("\t")[0])); if (addrs.size()>=64) break; }
    long t0=System.currentTimeMillis(); Map<Address,String> serial=new HashMap<>();
    for (Address a: addrs) serial.put(a, work(a));
    long t1=System.currentTimeMillis();
    ExecutorService ex = Executors.newFixedThreadPool(8); Map<Address,Future<String>> fut=new HashMap<>();
    for (Address a: addrs) fut.put(a, ex.submit(() -> work(a)));
    int mismatch=0, errors=0;
    for (Address a: addrs) { try { if (!fut.get(a).get().equals(serial.get(a))) mismatch++; } catch (Exception e) { errors++; println("ERR "+a+" "+e); } }
    ex.shutdown(); long t2=System.currentTimeMillis();
    println("n="+addrs.size()+" serial_ms="+(t1-t0)+" parallel8_ms="+(t2-t1)+" mismatch="+mismatch+" errors="+errors);
  }
}
