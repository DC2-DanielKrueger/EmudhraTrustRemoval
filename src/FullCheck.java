import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Checks this system for the eMudhra CA compromise by running the other tools. Changes nothing.
 *
 * <pre>
 * java FullCheck.java
 * </pre>
 *
 * Exit code 0 if every check is GOOD, 1 if any is BAD, 2 if a check could not run.
 */
public class FullCheck {

    public static void main(String[] args) throws Exception {
        Map<String, String[]> checks = new LinkedHashMap<>();
        checks.put("This JVM rejects the compromised chains", new String[]{"CheckJavaTrust"});
        checks.put("Trust stores (OS CA bundle, this JVM, installed JDKs)", new String[]{"RemoveEmudhraRoots", "--all-jdks"});
        checks.put("Installed Node.js", new String[]{"CheckInstalledNode"});

        Map<String, Integer> results = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> check : checks.entrySet()) {
            System.out.println("############ " + check.getKey());
            results.put(check.getKey(), run(check.getValue()));
            System.out.println();
        }

        int worst = 0;
        System.out.println("############ Summary");
        for (Map.Entry<String, Integer> r : results.entrySet()) {
            int code = r.getValue();
            System.out.println("  " + (code == 0 ? "GOOD " : code == 1 ? "BAD  " : "ERROR") + "  " + r.getKey());
            worst = Math.max(worst, Math.min(code, 2));
        }
        System.out.println();
        System.out.println(worst == 0 ? "==> GOOD: no exposure to the eMudhra CA compromise found."
                : worst == 1 ? "==> BAD: this system still trusts the compromised certificates. See the checks above."
                : "==> INCONCLUSIVE: a check could not run. See the checks above.");
        System.exit(worst);
    }

    /** Runs a tool in a new JVM (the tools call System.exit) and returns its exit code. */
    private static int run(String[] tool) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(Paths.get(System.getProperty("java.home"), "bin", "java").toString());
        Path classes = compiledLocation();
        if (classes != null) {
            cmd.add("-cp");
            cmd.add(classes.toString());
            cmd.add(tool[0]);
        } else {
            Path source = sourceDirectory().resolve(tool[0] + ".java").toAbsolutePath().normalize();
            if (!Files.isRegularFile(source)) {
                System.out.println("ERROR: " + source + " not found. Run FullCheck from the repository root.");
                return 2;
            }
            cmd.add(source.toString());
        }
        for (int i = 1; i < tool.length; i++) cmd.add(tool[i]);
        return new ProcessBuilder(cmd).inheritIO().start().waitFor();
    }

    /** The directory or jar holding FullCheck.class, or null when running from source. */
    private static Path compiledLocation() {
        try {
            Path p = Paths.get(FullCheck.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            return p.toString().endsWith(".java") ? null : p;
        } catch (Exception e) {
            return null; // Java 11 source launcher: no code source
        }
    }

    /** Where the sibling .java files are: next to this file (Java 22+ reports it), else src/ or the current directory. */
    private static Path sourceDirectory() {
        String self = System.getProperty("jdk.launcher.sourcefile");
        if (self != null) return Paths.get(self).toAbsolutePath().getParent();
        Path src = Paths.get("src");
        return new File(src.toFile(), "CheckJavaTrust.java").isFile() ? src : Paths.get(".");
    }
}
