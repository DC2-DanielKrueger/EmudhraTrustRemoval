import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Checks which TLS certificates a JVM trusts by requesting URLs, curl-style.
 *
 * <pre>
 * java CheckJavaTrust.java [-v] [-k] [--cacert FILE [--storepass PASS]] [URL...]
 * </pre>
 *
 * Without URLs it requests the eMudhra test hosts. Each URL gets a GOOD/BAD verdict: the test hosts
 * serve chains signed with the compromised keys, so for them REJECTED is GOOD; for any other URL,
 * TRUSTED is GOOD. Exit code 0 if every verdict is GOOD, 1 if any is BAD, 2 if inconclusive.
 */
public class CheckJavaTrust {

    private static final String TEST_DOMAIN = ".we-have-a-problem.com";

    private static final String[] DEFAULT_URLS = {
            "https://dv-g3b-emudhra" + TEST_DOMAIN + "/",
            "https://dv-g3b-aaa-emudhra" + TEST_DOMAIN + "/",
    };

    private enum Outcome { TRUSTED, REJECTED, ERROR, UNVERIFIED }

    private enum Verdict { GOOD, BAD, INCONCLUSIVE }

    public static void main(String[] args) throws Exception {
        boolean verbose = false;
        boolean insecure = false;
        String cacert = null;
        String storepass = "changeit";
        List<String> urls = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-v": verbose = true; break;
                case "-k": insecure = true; break;
                case "--cacert": cacert = args[++i]; break;
                case "--storepass": storepass = args[++i]; break;
                case "-h": case "--help": usage(); return;
                default:
                    if (args[i].startsWith("-")) { System.err.println("unknown option " + args[i]); usage(); System.exit(2); }
                    urls.add(args[i]);
            }
        }
        if (urls.isEmpty()) urls = Arrays.asList(DEFAULT_URLS);

        X509TrustManager delegate = trustManager(cacert, storepass);
        System.out.println("JVM " + System.getProperty("java.version") + " (" + System.getProperty("java.vendor") + ") at " + System.getProperty("java.home"));
        System.out.println("trust store: " + (cacert != null ? cacert : defaultTrustStore()) + " (" + delegate.getAcceptedIssuers().length + " roots)" + (insecure ? ", verification DISABLED (-k)" : ""));

        int good = 0, bad = 0, inconclusive = 0;
        for (String url : urls) {
            System.out.println();
            Verdict v = verdict(url, request(url, delegate, insecure, verbose));
            if (v == Verdict.GOOD) good++; else if (v == Verdict.BAD) bad++; else inconclusive++;
        }

        System.out.println();
        if (bad > 0) {
            System.out.println("==> BAD: " + bad + " of " + urls.size() + " URLs have the wrong outcome. "
                    + "If a test host was TRUSTED, this JVM still trusts a root the compromised eMudhra intermediates chain to.");
            System.exit(1);
        } else if (inconclusive > 0) {
            System.out.println("==> INCONCLUSIVE: " + inconclusive + " of " + urls.size() + " URLs could not be checked (" + good + " GOOD).");
            System.exit(2);
        } else {
            System.out.println("==> GOOD: all " + good + " URLs behave as expected.");
            System.exit(0);
        }
    }

    private static Verdict verdict(String url, Outcome outcome) {
        boolean testHost = URI.create(url).getHost().endsWith(TEST_DOMAIN);
        Verdict v;
        String why;
        if (outcome == Outcome.ERROR || outcome == Outcome.UNVERIFIED) {
            v = Verdict.INCONCLUSIVE;
            why = outcome == Outcome.ERROR ? "no TLS verdict (network error)" : "verification disabled with -k";
        } else if (testHost) {
            v = outcome == Outcome.REJECTED ? Verdict.GOOD : Verdict.BAD;
            why = v == Verdict.GOOD ? "compromised chain rejected" : "compromised chain TRUSTED";
        } else {
            v = outcome == Outcome.TRUSTED ? Verdict.GOOD : Verdict.BAD;
            why = v == Verdict.GOOD ? "normal site trusted" : "normal site rejected, trust store may be broken";
        }
        System.out.println("VERDICT: " + v + " - " + why);
        return v;
    }

    private static Outcome request(String url, X509TrustManager delegate, boolean insecure, boolean verbose) throws Exception {
        RecordingTrustManager recorder = new RecordingTrustManager(delegate, insecure);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, new TrustManager[]{recorder}, null);

        HttpURLConnection conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            https.setSSLSocketFactory(ctx.getSocketFactory());
            if (insecure) https.setHostnameVerifier((host, session) -> true);
        }
        conn.setConnectTimeout(10_000);
        conn.setReadTimeout(10_000);
        conn.setInstanceFollowRedirects(false);
        try {
            int status = conn.getResponseCode();
            System.out.println("* " + url);
            printChain(recorder.chain, verbose);
            System.out.println("< HTTP " + status + " " + (conn.getResponseMessage() == null ? "" : conn.getResponseMessage()));
            System.out.println(insecure ? "RESULT: connected (verification disabled)" : "RESULT: TRUSTED - this JVM accepts the server's certificate chain");
            return insecure ? Outcome.UNVERIFIED : Outcome.TRUSTED;
        } catch (SSLException e) {
            System.out.println("* " + url);
            printChain(recorder.chain, verbose);
            System.out.println("RESULT: REJECTED - " + rootCause(e));
            return Outcome.REJECTED;
        } catch (Exception e) {
            System.out.println("* " + url);
            System.out.println("RESULT: ERROR - " + e);
            return Outcome.ERROR;
        } finally {
            conn.disconnect();
        }
    }

    private static void printChain(X509Certificate[] chain, boolean verbose) throws Exception {
        if (chain == null) return;
        for (int i = 0; i < chain.length; i++) {
            X509Certificate c = chain[i];
            System.out.println("  " + i + " s: " + c.getSubjectX500Principal().getName());
            System.out.println("    i: " + c.getIssuerX500Principal().getName());
            if (verbose) {
                System.out.println("    valid " + c.getNotBefore() + " .. " + c.getNotAfter() + (c.getBasicConstraints() >= 0 ? ", CA" : ", leaf"));
                System.out.println("    sha256 " + fingerprint(c));
            }
        }
    }

    private static X509TrustManager trustManager(String cacert, String storepass) throws Exception {
        KeyStore ks = null;
        if (cacert != null) {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
            try (InputStream in = new FileInputStream(cacert)) {
                ks.load(in, storepass.toCharArray());
            }
        }
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks); // null = the JVM's default trust store
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) return (X509TrustManager) tm;
        }
        throw new IllegalStateException("no X509TrustManager");
    }

    private static String defaultTrustStore() {
        String prop = System.getProperty("javax.net.ssl.trustStore");
        return prop != null ? prop : System.getProperty("java.home") + "/lib/security/cacerts";
    }

    private static String fingerprint(X509Certificate c) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(sb.length() == 0 ? "" : ":").append(String.format("%02X", b));
        return sb.toString();
    }

    private static String rootCause(Throwable t) {
        while (t.getCause() != null) t = t.getCause();
        return t.getClass().getSimpleName() + ": " + t.getMessage();
    }

    private static void usage() {
        System.out.println("usage: java CheckJavaTrust.java [-v] [-k] [--cacert FILE [--storepass PASS]] [URL...]");
        System.out.println("  no URL      request the eMudhra test hosts (REJECTED there is GOOD)");
        System.out.println("  exit code   0 all GOOD, 1 any BAD, 2 inconclusive");
        System.out.println("  -v          print validity and SHA-256 fingerprint of each certificate");
        System.out.println("  -k          do not verify the certificate chain (like curl -k)");
        System.out.println("  --cacert    use this keystore (e.g. another JDK's cacerts) instead of the JVM default");
    }

    /** Delegates trust decisions, but keeps the presented chain so it can be shown even when rejected. */
    private static final class RecordingTrustManager implements X509TrustManager {
        private final X509TrustManager delegate;
        private final boolean insecure;
        X509Certificate[] chain;

        RecordingTrustManager(X509TrustManager delegate, boolean insecure) {
            this.delegate = delegate;
            this.insecure = insecure;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            if (!insecure) delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }
}
