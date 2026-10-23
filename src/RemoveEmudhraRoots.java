import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Removes the two roots that chain the compromised eMudhra intermediates from PEM bundles and Java
 * keystores: emSign ECC Root CA - G3 and Sectigo's AAA Certificate Services.
 *
 * <pre>
 * java RemoveEmudhraRoots.java [--apply] [--all-jdks] [--storepass PASS] [FILE...]
 * </pre>
 *
 * Without FILEs it targets the OS CA bundles that exist (macOS, Debian/Ubuntu, Alpine, RHEL, openSUSE
 * locations) and the running JVM's cacerts. Dry run unless
 * --apply. Exit code 0 if every target is clean (afterwards, with --apply), 1 if one still holds a
 * root, 2 on errors.
 */
public class RemoveEmudhraRoots {

    // Matched by fingerprint, not name or alias: vendors name the keystore entries differently.
    private static final Map<String, String> BAD_ROOTS = new HashMap<>();
    static {
        BAD_ROOTS.put("86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", "emSign ECC Root CA - G3");
        BAD_ROOTS.put("D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", "AAA Certificate Services");
    }

    /** OS CA bundles checked by default when present (several are symlinks to one file on some distributions). */
    private static final String[] OS_BUNDLES = {
            "/etc/ssl/cert.pem",                                  // macOS, Alpine, BSD
            "/etc/ssl/certs/ca-certificates.crt",                 // Debian, Ubuntu, Alpine, Arch
            "/etc/pki/tls/certs/ca-bundle.crt",                   // RHEL, Fedora
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  // RHEL, Fedora
            "/etc/ssl/ca-bundle.pem",                             // openSUSE
    };

    private static final String BACKUP_SUFFIX = ".bak-emsign";

    private static final Set<Path> SEEN_REAL_PATHS = new HashSet<>();

    // A PEM block plus any comment header before it; END CERTIFICATE closes the block.
    private static final Pattern PEM_CERT = Pattern.compile(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----\\r?\\n?", Pattern.DOTALL);

    private static boolean apply;
    private static String storepass = "changeit";

    public static void main(String[] args) throws Exception {
        Set<Path> targets = new LinkedHashSet<>();
        boolean allJdks = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--apply": apply = true; break;
                case "--all-jdks": allJdks = true; break;
                case "--storepass": storepass = args[++i]; break;
                case "-h": case "--help": usage(); return;
                default:
                    if (args[i].startsWith("-")) { System.err.println("unknown option " + args[i]); usage(); System.exit(2); }
                    Path given = Paths.get(args[i]);
                    if (Files.isRegularFile(given)) addIfPresent(targets, given); else targets.add(given); // missing: reported as an error
            }
        }
        if (targets.isEmpty()) {
            for (String bundle : OS_BUNDLES) addIfPresent(targets, Paths.get(bundle));
            addIfPresent(targets, jvmCacerts(Paths.get(System.getProperty("java.home"))));
        }
        if (allJdks) for (Path cacerts : installedJdkCacerts()) addIfPresent(targets, cacerts);

        System.out.println(apply ? "Mode: APPLY (files are changed, a " + BACKUP_SUFFIX + " backup is kept)"
                                 : "Mode: dry run (nothing is changed; re-run with --apply)");
        int worst = 0;
        for (Path target : targets) {
            System.out.println();
            System.out.println("== " + target);
            worst = Math.max(worst, process(target));
        }
        System.out.println();
        System.out.println(worst == 0 ? "==> GOOD: no target trusts either root."
                : worst == 1 ? "==> BAD: a target still trusts a compromised root." + (apply ? "" : " Re-run with --apply to remove it.")
                : "==> ERROR: some targets could not be processed (see above).");
        System.exit(worst);
    }

    /** 0 = clean, 1 = still contains a root (in a dry run: would be removed), 2 = error. */
    private static int process(Path target) {
        try {
            if (!Files.isRegularFile(target)) {
                System.out.println("  skipped: not a file");
                return 2;
            }
            byte[] content = Files.readAllBytes(target);
            String head = new String(content, 0, Math.min(content.length, 4096), StandardCharsets.US_ASCII);
            return head.contains("-----BEGIN CERTIFICATE-----") ? processPem(target, content) : processKeystore(target, content);
        } catch (AccessDeniedException e) {
            System.out.println("  ERROR: permission denied, run with sudo (" + e.getMessage() + ")");
            return 2;
        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            return 2;
        }
    }

    private static int processPem(Path target, byte[] content) throws Exception {
        String text = new String(content, StandardCharsets.UTF_8);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        StringBuilder kept = new StringBuilder();
        List<String> removed = new ArrayList<>();
        int total = 0;
        int blockStart = 0; // start of the current block, including its comment header
        Matcher m = PEM_CERT.matcher(text);
        while (m.find()) {
            total++;
            String block = text.substring(blockStart, m.end());
            X509Certificate cert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(m.group().getBytes(StandardCharsets.US_ASCII)));
            String bad = BAD_ROOTS.get(sha256(cert));
            if (bad != null) removed.add(bad); else kept.append(block);
            blockStart = m.end();
        }
        kept.append(text.substring(blockStart));
        System.out.println("  PEM bundle, " + total + " certificates");
        if (removed.isEmpty()) { System.out.println("  clean: contains neither root"); return 0; }
        report(removed);
        if (!apply) return 1;
        backup(target, content);
        Files.write(target, kept.toString().getBytes(StandardCharsets.UTF_8)); // in place: keeps owner and mode
        System.out.println("  written: " + (total - removed.size()) + " certificates left");
        return verifyPem(target);
    }

    private static int processKeystore(Path target, byte[] content) throws Exception {
        KeyStore ks = loadKeystore(content);
        List<String> removedAliases = new ArrayList<>();
        List<String> removed = new ArrayList<>();
        for (String alias : Collections.list(ks.aliases())) {
            Certificate c = ks.getCertificate(alias);
            if (!(c instanceof X509Certificate)) continue;
            String bad = BAD_ROOTS.get(sha256((X509Certificate) c));
            if (bad != null) { removedAliases.add(alias); removed.add(bad + " (alias \"" + alias + "\")"); }
        }
        System.out.println("  " + ks.getType() + " keystore, " + ks.size() + " entries");
        if (removed.isEmpty()) { System.out.println("  clean: contains neither root"); return 0; }
        report(removed);
        if (!apply) return 1;
        backup(target, content);
        for (String alias : removedAliases) ks.deleteEntry(alias);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ks.store(out, storepass.toCharArray());
        try (OutputStream os = new FileOutputStream(target.toFile())) { // in place: keeps owner and mode
            out.writeTo(os);
        }
        System.out.println("  written: " + ks.size() + " entries left");
        return verifyKeystore(target);
    }

    private static KeyStore loadKeystore(byte[] content) throws Exception {
        // Typed by magic number: since Java 9 a PKCS12 KeyStore also loads JKS files, so trying
        // types in order would mislabel a JKS cacerts (Java 8) as PKCS12.
        String type = startsWith(content, 0xFE, 0xED, 0xFE, 0xED) ? "JKS"
                : startsWith(content, 0xCE, 0xCE, 0xCE, 0xCE) ? "JCEKS"
                : "PKCS12";
        try {
            KeyStore ks = KeyStore.getInstance(type);
            ks.load(new ByteArrayInputStream(content), storepass.toCharArray());
            return ks;
        } catch (Exception e) {
            throw new IOException("neither a PEM bundle nor a " + type + " keystore readable with the given --storepass", e);
        }
    }

    private static boolean startsWith(byte[] content, int... magic) {
        if (content.length < magic.length) return false;
        for (int i = 0; i < magic.length; i++) if ((content[i] & 0xFF) != magic[i]) return false;
        return true;
    }

    private static int verifyPem(Path target) throws Exception {
        String text = new String(Files.readAllBytes(target), StandardCharsets.UTF_8);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Matcher m = PEM_CERT.matcher(text);
        while (m.find()) {
            X509Certificate c = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(m.group().getBytes(StandardCharsets.US_ASCII)));
            if (BAD_ROOTS.containsKey(sha256(c))) { System.out.println("  VERIFY FAILED: root still present"); return 1; }
        }
        System.out.println("  verified: neither root present");
        return 0;
    }

    private static int verifyKeystore(Path target) throws Exception {
        KeyStore ks = loadKeystore(Files.readAllBytes(target));
        for (String alias : Collections.list(ks.aliases())) {
            Certificate c = ks.getCertificate(alias);
            if (c instanceof X509Certificate && BAD_ROOTS.containsKey(sha256((X509Certificate) c))) {
                System.out.println("  VERIFY FAILED: root still present");
                return 1;
            }
        }
        System.out.println("  verified: neither root present");
        return 0;
    }

    private static void report(List<String> removed) {
        for (String r : removed) System.out.println("  " + (apply ? "removing: " : "would remove: ") + r);
    }

    private static void backup(Path target, byte[] content) throws IOException {
        Path backup = Paths.get(target + BACKUP_SUFFIX);
        if (Files.exists(backup)) {
            System.out.println("  backup exists, kept as is: " + backup);
        } else {
            Files.write(backup, content);
            System.out.println("  backup: " + backup);
        }
    }

    private static Path jvmCacerts(Path javaHome) {
        Path modern = javaHome.resolve("lib/security/cacerts");
        return Files.exists(modern) ? modern : javaHome.resolve("jre/lib/security/cacerts"); // Java 8 layout
    }

    private static List<Path> installedJdkCacerts() throws IOException {
        List<Path> result = new ArrayList<>();
        Map<String, String> roots = new LinkedHashMap<>(); // JDK parent directory -> JDK home inside each entry
        roots.put("/Library/Java/JavaVirtualMachines", "Contents/Home");
        roots.put(System.getProperty("user.home") + "/Library/Java/JavaVirtualMachines", "Contents/Home");
        roots.put("/usr/lib/jvm", "");
        for (Map.Entry<String, String> root : roots.entrySet()) {
            Path dir = Paths.get(root.getKey());
            if (!Files.isDirectory(dir)) continue;
            try (DirectoryStream<Path> jdks = Files.newDirectoryStream(dir)) {
                for (Path jdk : jdks) {
                    Path cacerts = jvmCacerts(root.getValue().isEmpty() ? jdk : jdk.resolve(root.getValue()));
                    if (Files.isRegularFile(cacerts)) result.add(cacerts);
                }
            }
        }
        return result;
    }

    /** Adds an existing file once per real path, so symlinked bundles and JDK aliases are processed once. */
    private static void addIfPresent(Set<Path> targets, Path candidate) {
        if (!Files.isRegularFile(candidate)) return;
        Path real;
        try {
            real = candidate.toRealPath();
        } catch (IOException e) {
            real = candidate.toAbsolutePath();
        }
        if (SEEN_REAL_PATHS.add(real)) targets.add(candidate);
    }

    private static String sha256(X509Certificate c) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static void usage() {
        System.out.println("usage: java RemoveEmudhraRoots.java [--apply] [--all-jdks] [--storepass PASS] [FILE...]");
        System.out.println("  FILE        PEM bundle or Java keystore; default: the OS CA bundles present and this JVM's cacerts");
        System.out.println("  --apply     change the files (default is a dry run); keeps a " + BACKUP_SUFFIX + " backup");
        System.out.println("  --all-jdks  also every JDK under /Library/Java/JavaVirtualMachines, ~/Library/Java/JavaVirtualMachines and /usr/lib/jvm");
        System.out.println("  exit code   0 clean, 1 a root remains, 2 error (e.g. needs sudo)");
    }
}
