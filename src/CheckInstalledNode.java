import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds installed Node.js binaries and checks each against the eMudhra CA compromise.
 *
 * <pre>
 * java CheckInstalledNode.java [--offline] [NODE_BINARY...]
 * </pre>
 *
 * Node bundles its own root certificates, so only a Node release with an updated root store is
 * fixed. Each binary gets two checks: its version against the first fixed release of its line,
 * and (unless --offline) a live request to the eMudhra test hosts made by that binary itself,
 * which also catches NODE_OPTIONS / NODE_EXTRA_CA_CERTS pulling a bad root in from elsewhere.
 * Exit code 0 if every binary is GOOD (or none is installed), 1 if any is BAD, 2 if inconclusive.
 */
public class CheckInstalledNode {

    /** First release per major line that no longer trusts the roots (security releases, 20-21 Oct 2026). */
    private static final Map<Integer, int[]> FIXED = new TreeMap<>();
    static {
        FIXED.put(22, new int[]{22, 23, 4});
        FIXED.put(24, new int[]{24, 22, 1});
        FIXED.put(26, new int[]{26, 12, 1});
    }
    /** Lines after this one were first released after the fix; their version alone cannot be judged. */
    private static final int NEWEST_KNOWN_MAJOR = 26;

    private static final String[] TEST_HOSTS = {
            "dv-g3b-emudhra.we-have-a-problem.com",
            "dv-g3b-aaa-emudhra.we-have-a-problem.com",
    };

    // Run by each node binary. Untrusted-chain errors carry codes such as
    // UNABLE_TO_GET_ISSUER_CERT_LOCALLY or SELF_SIGNED_CERT_IN_CHAIN.
    private static final String LIVE_SCRIPT = String.join("\n",
            "const https = require('https');",
            "const hosts = process.argv.slice(1);",
            "let left = hosts.length;",
            "for (const host of hosts) {",
            "  let done = false;",
            "  const report = (s) => { if (!done) { done = true; console.log(host + ' ' + s); } };",
            "  const req = https.get({ host, path: '/', timeout: 10000 }, (res) => { report('TRUSTED'); res.resume(); });",
            "  req.on('timeout', () => req.destroy(new Error('timeout')));",
            "  req.on('error', (e) => report((/CERT|ISSUER|SIGNATURE|SELF_SIGNED/.test(e.code || '') ? 'REJECTED ' : 'ERROR ') + (e.code || e.message)));",
            "}");

    private enum Verdict { GOOD, BAD, INCONCLUSIVE }

    public static void main(String[] args) throws Exception {
        boolean offline = false;
        List<Path> explicit = new ArrayList<>();
        for (String arg : args) {
            switch (arg) {
                case "--offline": offline = true; break;
                case "-h": case "--help": usage(); return;
                default:
                    if (arg.startsWith("-")) { System.err.println("unknown option " + arg); usage(); System.exit(2); }
                    explicit.add(Paths.get(arg));
            }
        }

        Map<Path, List<String>> binaries = explicit.isEmpty() ? discover() : new LinkedHashMap<>();
        for (Path p : explicit) add(binaries, p, "given on the command line");

        printEnvironmentHints();
        if (binaries.isEmpty()) {
            System.out.println();
            System.out.println("==> GOOD: no Node.js installation found, nothing to fix.");
            System.exit(0);
        }

        int good = 0, bad = 0, inconclusive = 0;
        for (Map.Entry<Path, List<String>> e : binaries.entrySet()) {
            System.out.println();
            Verdict v = check(e.getKey(), e.getValue(), offline);
            if (v == Verdict.GOOD) good++; else if (v == Verdict.BAD) bad++; else inconclusive++;
        }

        int total = binaries.size();
        System.out.println();
        if (bad > 0) {
            System.out.println("==> BAD: " + bad + " of " + total + " Node.js installations still trust the compromised roots. "
                    + "Upgrade to " + fixedList() + " or later, or remove the installation.");
            System.exit(1);
        } else if (inconclusive > 0) {
            System.out.println("==> INCONCLUSIVE: " + inconclusive + " of " + total + " Node.js installations could not be judged (" + good + " GOOD).");
            System.exit(2);
        } else {
            System.out.println("==> GOOD: all " + total + " Node.js installations reject the compromised roots.");
            System.exit(0);
        }
    }

    private static Verdict check(Path node, List<String> foundVia, boolean offline) {
        System.out.println("== " + node + "  (" + String.join(", ", foundVia) + ")");
        String raw;
        try {
            raw = run(node, 15, "--version").trim();
        } catch (Exception e) {
            System.out.println("  ERROR: cannot run it: " + e.getMessage());
            System.out.println("VERDICT: INCONCLUSIVE");
            return Verdict.INCONCLUSIVE;
        }
        int[] version = parse(raw);
        if (version == null) {
            System.out.println("  ERROR: unexpected version output \"" + raw + "\"");
            System.out.println("VERDICT: INCONCLUSIVE");
            return Verdict.INCONCLUSIVE;
        }

        Verdict byVersion = versionVerdict(raw, version);

        Verdict live = Verdict.INCONCLUSIVE;
        if (offline) {
            System.out.println("  live:    skipped (--offline)");
        } else {
            live = liveVerdict(node);
        }

        if (byVersion == Verdict.BAD && live == Verdict.GOOD) {
            // Seen with builds that use an external CA bundle (e.g. Homebrew's) instead of Node's bundled roots.
            System.out.println("  note:    rejected live although the version is unfixed: this build likely uses a separately updated CA store."
                    + " It stays BAD because a different environment or CA bundle can make it trust the roots again.");
        }
        Verdict overall;
        if (byVersion == Verdict.BAD || live == Verdict.BAD) overall = Verdict.BAD;
        else if (live == Verdict.GOOD || (offline && byVersion == Verdict.GOOD)) overall = Verdict.GOOD;
        else overall = Verdict.INCONCLUSIVE;
        System.out.println("VERDICT: " + overall);
        return overall;
    }

    private static Verdict versionVerdict(String raw, int[] v) {
        int[] fixed = FIXED.get(v[0]);
        if (fixed != null) {
            boolean ok = compare(v, fixed) >= 0;
            System.out.println("  version: " + raw + " -> " + (ok ? "GOOD" : "BAD") + " (line " + v[0] + " is fixed from " + str(fixed) + ")");
            return ok ? Verdict.GOOD : Verdict.BAD;
        }
        if (v[0] > NEWEST_KNOWN_MAJOR) {
            System.out.println("  version: " + raw + " -> UNKNOWN (newer than the lines this tool knows; the live check decides)");
            return Verdict.INCONCLUSIVE;
        }
        System.out.println("  version: " + raw + " -> BAD (line " + v[0] + " got no fixed release; upgrade to " + fixedList() + " or later)");
        return Verdict.BAD;
    }

    private static Verdict liveVerdict(Path node) {
        List<String> cmd = new ArrayList<>();
        cmd.add("-e");
        cmd.add(LIVE_SCRIPT);
        for (String h : TEST_HOSTS) cmd.add(h);
        String out;
        try {
            out = run(node, 40, cmd.toArray(new String[0]));
        } catch (Exception e) {
            System.out.println("  live:    ERROR " + e.getMessage());
            return Verdict.INCONCLUSIVE;
        }
        Verdict result = Verdict.GOOD;
        int answered = 0;
        for (String line : out.split("\\R")) {
            if (line.isEmpty()) continue;
            String[] parts = line.split(" ", 2);
            if (!Arrays.asList(TEST_HOSTS).contains(parts[0])) {
                // Anything else is Node's own output, e.g. a warning about NODE_EXTRA_CA_CERTS.
                System.out.println("  node:    " + line);
                continue;
            }
            answered++;
            String status = parts.length > 1 ? parts[1] : "";
            String meaning;
            if (status.startsWith("REJECTED")) {
                meaning = "GOOD";
            } else if (status.startsWith("TRUSTED")) {
                meaning = "BAD";
                result = Verdict.BAD;
            } else {
                meaning = "INCONCLUSIVE";
                if (result == Verdict.GOOD) result = Verdict.INCONCLUSIVE;
            }
            System.out.println("  live:    " + parts[0] + " " + status + " -> " + meaning);
        }
        if (answered < TEST_HOSTS.length && result == Verdict.GOOD) result = Verdict.INCONCLUSIVE;
        return result;
    }

    // --- discovery ----------------------------------------------------------------------------

    private static Map<Path, List<String>> discover() throws IOException {
        Map<Path, List<String>> found = new LinkedHashMap<>();
        String path = System.getenv("PATH");
        if (path != null) {
            for (String dir : path.split(File.pathSeparator)) {
                if (!dir.isEmpty()) add(found, Paths.get(dir, "node"), "PATH");
            }
        }
        String home = System.getProperty("user.home");
        String nvmDir = System.getenv("NVM_DIR") != null ? System.getenv("NVM_DIR") : home + "/.nvm";
        addVersions(found, Paths.get(nvmDir, "versions/node"), "bin/node", "nvm");
        addVersions(found, Paths.get(home, ".local/share/fnm/node-versions"), "installation/bin/node", "fnm");
        addVersions(found, Paths.get(home, "Library/Application Support/fnm/node-versions"), "installation/bin/node", "fnm");
        addVersions(found, Paths.get(home, ".volta/tools/image/node"), "bin/node", "Volta");
        addVersions(found, Paths.get(home, ".asdf/installs/nodejs"), "bin/node", "asdf");
        addVersions(found, Paths.get(home, ".local/share/mise/installs/node"), "bin/node", "mise");
        for (String prefix : new String[]{"/opt/homebrew", "/usr/local"}) {
            add(found, Paths.get(prefix, "bin/node"), prefix);
            addMatching(found, Paths.get(prefix, "opt"), "node@", "bin/node", "Homebrew");
        }
        add(found, Paths.get("/usr/bin/node"), "/usr/bin");
        return found;
    }

    private static void addVersions(Map<Path, List<String>> found, Path dir, String binary, String via) throws IOException {
        addMatching(found, dir, "", binary, via);
    }

    private static void addMatching(Map<Path, List<String>> found, Path dir, String prefix, String binary, String via) throws IOException {
        if (!Files.isDirectory(dir)) return;
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir, prefix + "*")) {
            for (Path entry : entries) add(found, entry.resolve(binary), via);
        }
    }

    /** Keyed by real path, so symlinks (PATH shims, Homebrew links) collapse onto one installation. */
    private static void add(Map<Path, List<String>> found, Path candidate, String via) {
        if (!Files.isRegularFile(candidate) || !Files.isExecutable(candidate)) return;
        Path real;
        try {
            real = candidate.toRealPath();
        } catch (IOException e) {
            real = candidate.toAbsolutePath();
        }
        List<String> vias = found.computeIfAbsent(real, k -> new ArrayList<>());
        if (!vias.contains(via)) vias.add(via);
    }

    // --- helpers ------------------------------------------------------------------------------

    private static void printEnvironmentHints() {
        String extra = System.getenv("NODE_EXTRA_CA_CERTS");
        String options = System.getenv("NODE_OPTIONS");
        if (extra != null) System.out.println("note: NODE_EXTRA_CA_CERTS=" + extra + " adds certificates to every Node; it must not contain either root");
        if (options != null && (options.contains("use-openssl-ca") || options.contains("use-system-ca"))) {
            System.out.println("note: NODE_OPTIONS=" + options + " makes Node use the OS trust store, so the OS store must be fixed too");
        }
    }

    private static String run(Path binary, int timeoutSeconds, String... args) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>();
        cmd.add(binary.toString());
        for (String a : args) cmd.add(a);
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        p.getOutputStream().close();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream in = p.getInputStream()) {
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
            } catch (IOException ignored) {
                // process killed on timeout
            }
        });
        reader.start();
        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IOException("timed out after " + timeoutSeconds + "s");
        }
        reader.join(1000);
        return out.toString(StandardCharsets.UTF_8.name());
    }

    private static int[] parse(String version) {
        Matcher m = Pattern.compile("^v?(\\d+)\\.(\\d+)\\.(\\d+)").matcher(version);
        if (!m.find()) return null;
        return new int[]{Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2)), Integer.parseInt(m.group(3))};
    }

    private static int compare(int[] a, int[] b) {
        for (int i = 0; i < 3; i++) if (a[i] != b[i]) return Integer.compare(a[i], b[i]);
        return 0;
    }

    private static String str(int[] v) {
        return v[0] + "." + v[1] + "." + v[2];
    }

    private static String fixedList() {
        List<String> s = new ArrayList<>();
        for (int[] v : FIXED.values()) s.add(str(v));
        return String.join(", ", s);
    }

    private static void usage() {
        System.out.println("usage: java CheckInstalledNode.java [--offline] [NODE_BINARY...]");
        System.out.println("  no binary   check every node on PATH and in nvm, fnm, Volta, asdf, mise, Homebrew and /usr/local");
        System.out.println("  --offline   only compare versions; skip the live request to the eMudhra test hosts");
        System.out.println("  fixed from  " + fixedList() + " (lines 20, 23, 25 and older got no fix)");
        System.out.println("  exit code   0 all GOOD or none installed, 1 any BAD, 2 inconclusive");
    }
}
