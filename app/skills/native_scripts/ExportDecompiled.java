// Export decompiled functions from the current program to a C-like text file.
// @category Audit
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class ExportDecompiled extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = System.getenv("GHIDRA_DECOMP_OUT");
        if (out == null || out.isEmpty()) {
            println("GHIDRA_DECOMP_OUT not set");
            return;
        }
        DecompInterface ifc = new DecompInterface();
        if (!ifc.openProgram(currentProgram)) {
            println("decompiler open failed: " + ifc.getLastMessage());
            return;
        }
        int count = 0;
        PrintWriter w = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(out), StandardCharsets.UTF_8));
        try {
            w.println("/* Ghidra decompiled: " + currentProgram.getName() + " */");
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (monitor.isCancelled()) {
                    break;
                }
                if (f.isExternal()) {
                    continue;
                }
                w.println("\n/* FUNC " + f.getName() + " @ " + f.getEntryPoint() + " */");
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    w.println(r.getDecompiledFunction().getC());
                    count++;
                }
            }
        } finally {
            w.close();
            ifc.dispose();
        }
        println("decompiled functions: " + count + " -> " + out);
    }
}
