package com.securepay.debug;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Session-scoped NDJSON for debug ingest. Resolves {@code debug-619fb6.log} using, in order:
 * <ol>
 *   <li>{@code -Dsecurepay.debug.ndjson.path=} (file path, or directory + default filename)</li>
 *   <li>Maven module root found by walking up from {@code application.properties} on the file classpath (IDE / {@code target/classes})</li>
 *   <li>First ancestor of {@code user.dir} that contains {@code pom.xml}</li>
 *   <li>{@code user.dir} + default filename</li>
 * </ol>
 */
public final class DebugNdjson619 {

    private static final String SESSION = "619fb6";
    private static final String FILENAME = "debug-" + SESSION + ".log";

    private static volatile Path resolvedLogPath;

    private DebugNdjson619() {}

    /** One line at startup so the log file exists even before any wallet/register call. */
    public static void appendReadyProbe() {
        writeLine(
                "P0",
                "DebugNdjson619Warmup",
                "application_ready",
                "{\"logPath\":\"" + escape(logPath().toAbsolutePath().toString()) + "\"}");
    }

    public static void append(String hypothesisId, String location, String message, String dataJson) {
        writeLine(hypothesisId, location, message, dataJson);
    }

    private static void writeLine(String hypothesisId, String location, String message, String dataJson) {
        String line = "{\"sessionId\":\"" + SESSION + "\",\"hypothesisId\":\"" + escape(hypothesisId)
                + "\",\"location\":\"" + escape(location) + "\",\"message\":\"" + escape(message)
                + "\",\"data\":" + dataJson + ",\"timestamp\":" + System.currentTimeMillis() + "}\n";
        try {
            Files.writeString(logPath(), line, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (Exception ignored) {
            // debug ingest only
        }
    }

    private static Path logPath() {
        Path p = resolvedLogPath;
        if (p != null) {
            return p;
        }
        synchronized (DebugNdjson619.class) {
            if (resolvedLogPath == null) {
                resolvedLogPath = resolveLogPath();
            }
            return resolvedLogPath;
        }
    }

    private static Path resolveLogPath() {
        String override = System.getProperty("securepay.debug.ndjson.path");
        if (override != null && !override.isBlank()) {
            Path p = Path.of(override.trim()).toAbsolutePath().normalize();
            if (Files.isDirectory(p)) {
                return p.resolve(FILENAME).normalize();
            }
            return p;
        }

        Path fromClasspath = resolveMavenRootFromClasspath();
        if (fromClasspath != null) {
            return fromClasspath.resolve(FILENAME).normalize();
        }

        Path start = Path.of(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();
        Path dir = start;
        for (int i = 0; i < 16 && dir != null; i++) {
            try {
                if (Files.isRegularFile(dir.resolve("pom.xml"))) {
                    return dir.resolve(FILENAME).normalize();
                }
            } catch (Exception ignored) {
                // ignore and walk up
            }
            dir = dir.getParent();
        }
        return start.resolve(FILENAME).normalize();
    }

    /**
     * When running from the IDE or {@code mvn spring-boot:run}, {@code application.properties} is a
     * {@code file:} URL under {@code target/classes}; walking parents finds {@code pom.xml}.
     */
    private static Path resolveMavenRootFromClasspath() {
        try {
            URL u = DebugNdjson619.class.getClassLoader().getResource("application.properties");
            if (u == null || !"file".equals(u.getProtocol())) {
                return null;
            }
            Path propFile = Path.of(u.toURI()).toAbsolutePath().normalize();
            Path dir = propFile.getParent();
            for (int i = 0; i < 24 && dir != null; i++) {
                if (Files.isRegularFile(dir.resolve("pom.xml"))) {
                    return dir;
                }
                dir = dir.getParent();
            }
        } catch (Exception ignored) {
            // not a file classpath or unreadable
        }
        return null;
    }

    private static String escape(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
