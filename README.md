# eMudhra trust removal

Dependency-free Java tools for the October 2026 eMudhra CA compromise:

- **FullCheck** runs all checks below on this system, with one GOOD/BAD summary. Start here.
- **CheckJavaTrust** checks whether a JVM (or any trust store) still trusts the compromised certificates.
- **CheckInstalledNode** finds installed Node.js versions and checks that each is a fixed release.
- **RemoveEmudhraRoots** removes the affected roots from PEM bundles and Java keystores.

## Background

The private keys of eight eMudhra intermediate CAs (EM DV/OV/EV TLS CA and EM OV CS CA, generations G3B and G3C) can be recovered from their public certificates. Each intermediate exists twice: under eMudhra's **emSign ECC Root CA - G3** and cross-signed by Sectigo's **AAA Certificate Services**. A client that trusts either root accepts certificates forged with those keys.

Browsers block the intermediates through their own revocation mechanisms. Most other clients do not check revocation, so they stay exposed until the roots are removed from their trust store:

- **Java**: every JDK/JRE uses its own `cacerts`, not the OS store.
- **Node.js**: bundles its own root certificates, so only a fixed Node release helps.
- **macOS command-line tools** (`/usr/bin/curl`, `git`, `openssl`, system `python3`) read `/etc/ssl/cert.pem`, which Apple had not updated as of macOS 27.0.1.

Details: <https://emudhra.we-have-a-problem.com/> and [Mozilla bug 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449).

| Root | SHA-256 fingerprint |
|---|---|
| emSign ECC Root CA - G3 | `86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B` |
| AAA Certificate Services | `D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4` |

Removing these roots also breaks any legitimate server whose chain ends only at one of them. `emSign Root CA - G1` is not affected and is left alone.

## Requirements

Java 11 or newer. A JDK runs the files directly (`java src/CheckJavaTrust.java`). On a JRE without a compiler, such as a container image, compile them first and run the classes:

```sh
javac --release 11 -d out src/*.java
java -cp out FullCheck               # or CheckJavaTrust, CheckInstalledNode, RemoveEmudhraRoots
```

`RemoveEmudhraRoots` still edits the trust stores of older JDKs, including Java 8 (`jre/lib/security/cacerts`, JKS); it just has to run on Java 11 or newer.

## FullCheck: check this system

```sh
java src/FullCheck.java
```

No arguments, changes nothing. It runs, each in its own JVM:

1. `CheckJavaTrust`: the JVM running FullCheck rejects both compromised chains.
2. `RemoveEmudhraRoots --all-jdks` as a dry run: neither root is in the OS CA bundle, this JVM's `cacerts` or any installed JDK's.
3. `CheckInstalledNode`: every installed Node.js is a fixed release and rejects both chains.

```
############ Summary
  GOOD   This JVM rejects the compromised chains
  GOOD   Trust stores (OS CA bundle, this JVM, installed JDKs)
  GOOD   Installed Node.js

==> GOOD: no exposure to the eMudhra CA compromise found.
```

Exit code: `0` all GOOD, `1` any BAD, `2` a check could not run.

To check a container image (the images are usually JREs without a compiler), compile on the host and mount the classes:

```sh
javac --release 11 -d /tmp/emudhra src/*.java
docker run --rm -v /tmp/emudhra:/emudhra:ro --entrypoint java <image> -cp /emudhra FullCheck
``` On Java 11-21, run it from the repository root (or `src/`) so it finds the other tools; Java 22+ and compiled classes work from anywhere.

## CheckJavaTrust: check what a JVM trusts

```sh
java src/CheckJavaTrust.java                                  # the two eMudhra test hosts
java src/CheckJavaTrust.java -v https://example.com/          # any URL, with fingerprints
java src/CheckJavaTrust.java --cacert /path/to/cacerts        # another trust store
```

Each URL gets a verdict. The test hosts serve chains signed with the compromised keys, so for them **REJECTED is GOOD**; for any other URL, TRUSTED is GOOD.

```
VERDICT: GOOD - compromised chain rejected
==> GOOD: all 2 URLs behave as expected.
```

Exit code: `0` all GOOD, `1` any BAD, `2` inconclusive (network error, or `-k`).

In a JRE-only container, compile on the host and mount the classes:

```sh
javac --release 11 -d /tmp/check-java-trust src/CheckJavaTrust.java
docker run --rm -v /tmp/check-java-trust:/check-java-trust:ro --entrypoint java <image> -cp /check-java-trust CheckJavaTrust
```

## CheckInstalledNode: check installed Node.js versions

```sh
java src/CheckInstalledNode.java                     # every node it can find
java src/CheckInstalledNode.java /path/to/node       # specific binaries
java src/CheckInstalledNode.java --offline           # versions only, no network
```

It looks for `node` on `PATH` and in nvm, fnm, Volta, asdf, mise, Homebrew (`/opt/homebrew`, `/usr/local`, `node@*`) and `/usr/bin`, counting each installation once even when several paths link to it. Each one gets two checks:

1. **Version**: at least the first fixed release of its line. Only three lines got a fix:

   | Line | Fixed from |
   |---|---|
   | 22 | 22.23.4 |
   | 24 | 24.22.1 |
   | 26 | 26.12.1 |

   Lines 20, 23, 25 and older are end-of-life and got no fix, so they are always BAD. Lines newer than 26 are judged by the live check alone.
2. **Live**: that `node` binary requests both eMudhra test hosts and must reject them. This also catches `NODE_EXTRA_CA_CERTS` or `NODE_OPTIONS=--use-system-ca` pulling a bad root in from elsewhere.

An installation is GOOD only if both checks pass. Builds that use an external CA bundle instead of Node's own (Homebrew's, for example) can reject the test hosts on an unfixed version; they stay BAD, because a different CA bundle makes them trust the roots again. The fixed releases also block the compromised intermediates themselves.

Exit code: `0` all GOOD or no Node.js installed, `1` any BAD, `2` inconclusive.

## RemoveEmudhraRoots: remove the roots

```sh
java src/RemoveEmudhraRoots.java --all-jdks          # dry run: report only
sudo "$(/usr/libexec/java_home)/bin/java" src/RemoveEmudhraRoots.java --apply
```

- Targets the given files, or by default the OS CA bundles that exist and the running JVM's `cacerts`. OS bundles: `/etc/ssl/cert.pem` (macOS, Alpine), `/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu, Alpine), `/etc/pki/tls/certs/ca-bundle.crt` and `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` (RHEL, Fedora), `/etc/ssl/ca-bundle.pem` (openSUSE). `--all-jdks` adds every JDK under `/Library/Java/JavaVirtualMachines`, `~/Library/Java/JavaVirtualMachines` and `/usr/lib/jvm`. Paths that link to the same file are processed once.
- Matches the roots by SHA-256 fingerprint, so vendor-specific aliases don't matter. Handles PEM bundles and PKCS12/JKS keystores (JKS for Java 8), keeping each in its format.
- **Dry run unless `--apply`.** With `--apply` it writes a `<file>.bak-emsign` backup (never overwriting an existing one), rewrites the file in place (keeping owner and permissions), and verifies the result. Running it again changes nothing.
- Exit code: `0` clean, `1` a root remains (in a dry run: would be removed), `2` error (for example, a root-owned file without `sudo`).
- `--storepass` sets the keystore password; the default is the JDK's `changeit`.

To undo, copy the backup back: `sudo cp -p /etc/ssl/cert.pem.bak-emsign /etc/ssl/cert.pem`.

**Updates restore the roots.** A JDK, IDE or OS update replaces these files; on Linux, `update-ca-certificates` / `update-ca-trust` also regenerate the OS bundle, so prefer the distribution's fixed `ca-certificates` package there. Re-run the dry run after updating until vendors ship fixed trust stores. JDKs bundled in applications (IDEs, profilers) are not found by `--all-jdks`; pass their `cacerts` explicitly.

## License

[Apache License 2.0](LICENSE)
