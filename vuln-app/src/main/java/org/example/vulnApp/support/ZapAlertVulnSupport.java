package org.example.vulnApp.support;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

public final class ZapAlertVulnSupport {
    public static final long TIMING_MARGIN_MS = 1_500L;
    public static final double MAX_SLEEP_SECONDS = 60.0;

    public static final Pattern POSTGRES_SLEEP_PATTERN = Pattern.compile(
        "(?i)pg_sleep\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)"
    );

    public static final Pattern ORACLE_SLEEP_PATTERN = Pattern.compile(
        "DBMS_(?:SESSION|LOCK)\\s*\\.\\s*SLEEP\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    public static final long LEGACY_ORACLE_SLEEP_MS = 5_000L;

    public static final Pattern MYSQL_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?<![A-Za-z0-9_.])sleep\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\)|(?<![A-Za-z0-9_.])benchmark\\s*\\("
    );

    /**
     * ZAP 40020 uses Hypersonic's quoted Java UDF form:
     * "java.lang.Thread.sleep"(milliseconds). Older/local variants are accepted too.
     */
    public static final Pattern HSQL_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?:\\\"java\\.lang\\.Thread\\.sleep\\\"\\s*\\(\\s*(\\d+)\\s*\\)"
            + "|java\\.lang\\.thread\\.sleep\\s*\\(\\s*(\\d+)\\s*\\)"
            + "|call\\s+sleep\\s*\\(\\s*(\\d+(?:\\.\\d+)?)\\s*\\))"
    );

    public static final Pattern MSSQL_WAITFOR_PATTERN = Pattern.compile(
        "(?i)waitfor\\s+delay\\s+'0+:0+:(\\d+(?:\\.\\d+)?)'"
    );

    public static final Pattern SQLITE_RANDOMBLOB_PATTERN = Pattern.compile(
        "randomblob\\s*\\(\\s*(\\d+)(?:\\s*/\\s*(\\d+))?\\s*\\)",
        Pattern.CASE_INSENSITIVE
    );

    public static final long SQLITE_MIN_RANDOMBLOB_BYTES = 100_000L;
    public static final long SQLITE_MAX_SLEEP_MS = 8_000L;

    public static final Pattern OS_COMMAND_SLEEP_PATTERN = Pattern.compile(
        "(?i)(?:^|[;&|`\\s])(?:sleep\\s+(\\d{1,2})(?:\\b|\\s|$)|timeout(?:\\.exe)?\\s+(?:/t\\s+)?(\\d{1,2})(?:\\b|\\s|$)|ping\\s+(?:-c\\s+(\\d{1,2})|(?:127\\.0\\.0\\.1|localhost)\\s+-n\\s+(\\d{1,2})))"
    );

    /**
     * Blind SSTI payloads wrap OS commands inside template syntax and normally use "sleep N",
     * not SQL-style sleep(N). Keep this narrow so SQLi timing payloads do not trigger here.
     */
    public static final Pattern SSTI_SLEEP_PATTERN = Pattern.compile(
        "(?is)(?:<#assign|#set\\(|global\\.process|__import__|subprocess|system\\(|%x\\(|\\$\\{|#\\{|\\{\\{|<%=).*?sleep\\s*(?:\\(\\s*)?(\\d{1,2})(?:\\s*\\))?"
    );

    /** MongoDB time-based ZAP payloads contain JavaScript-ish syntax around sleep(N). */
    public static final Pattern MONGO_SLEEP_PATTERN = Pattern.compile(
        "(?is)(?:print\\s*\\(|var\\s+x|hex_md5|md5|mapReduce|\\|\\||0\\)??\\s*;\\s*)[^\\n\\r]*?sleep\\s*\\(\\s*(\\d{1,2}(?:\\.\\d+)?)\\s*\\)"
    );

    public static final Pattern SIMPLE_ARITHMETIC_PATTERN = Pattern.compile(
        "(\\d{2,7})\\s*([+*])\\s*(\\d{2,7})"
    );

    public static final String VALID_PADDING_ORACLE_TOKEN_HEX =
        "ffffffffffffffffffffffffffffff10";

    private ZapAlertVulnSupport() {
    }

    public static void sleepSecondsWithMargin(double seconds) {
        double boundedSeconds = Math.min(Math.max(seconds, 0.0), MAX_SLEEP_SECONDS);
        sleepMillis(Math.round(boundedSeconds * 1000.0) + TIMING_MARGIN_MS);
    }

    public static double firstMatchedNumber(Matcher matcher) {
        for (int i = 1; i <= matcher.groupCount(); i++) {
            String value = matcher.group(i);
            if (value != null) {
                return Double.parseDouble(value);
            }
        }
        return 0.0;
    }

    public static void sleepSecondsOrMillisWithMargin(double value) {
        if (value > MAX_SLEEP_SECONDS) {
            sleepMillis(Math.round(Math.min(value, MAX_SLEEP_SECONDS * 1000.0)) + TIMING_MARGIN_MS);
            return;
        }
        sleepSecondsWithMargin(value);
    }

    public static void sleepMillis(long millis) {
        try {
            Thread.sleep(Math.max(0L, millis));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public static long sqliteRandomblobDelayMillis(long blobBytes) {
        if (blobBytes < SQLITE_MIN_RANDOMBLOB_BYTES) {
            return 0L;
        }
        double ratio = (double) blobBytes / SQLITE_MIN_RANDOMBLOB_BYTES;
        double step = Math.max(1.0, Math.log10(ratio) + 1.0);
        return Math.min(Math.round(step * 900L), SQLITE_MAX_SLEEP_MS);
    }

    public static long sqliteRandomblobBytes(Matcher matcher) {
        long numerator = Long.parseLong(matcher.group(1));
        if (matcher.groupCount() >= 2 && matcher.group(2) != null) {
            long divisor = Math.max(1L, Long.parseLong(matcher.group(2)));
            return numerator / divisor;
        }
        return numerator;
    }

    public static String evaluateFirstArithmeticExpression(String value) {
        Matcher matcher = SIMPLE_ARITHMETIC_PATTERN.matcher(value == null ? "" : value);
        if (!matcher.find()) {
            return null;
        }
        long left = Long.parseLong(matcher.group(1));
        long right = Long.parseLong(matcher.group(3));
        long result = "*".equals(matcher.group(2)) ? left * right : left + right;
        return String.valueOf(result);
    }

    public static String safeLower(String value) {
        return value == null ? "" : value.toLowerCase(Locale.ROOT);
    }

    public static String escapeXml(String value) {
        return value == null ? "" : value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    public static ResponseEntity<String> text(String body) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(body);
    }

    public static ResponseEntity<String> html(String body) {
        return ResponseEntity.ok().contentType(MediaType.TEXT_HTML).body(body);
    }

    public static ResponseEntity<String> xml(String body) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_XML).body(body);
    }

    public static ResponseEntity<String> json(String body) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
