package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.HSQL_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.LEGACY_ORACLE_SLEEP_MS;
import static org.example.vulnApp.support.ZapAlertVulnSupport.MAX_SLEEP_SECONDS;
import static org.example.vulnApp.support.ZapAlertVulnSupport.MSSQL_WAITFOR_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.MYSQL_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.ORACLE_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.POSTGRES_SLEEP_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.SQLITE_RANDOMBLOB_PATTERN;
import static org.example.vulnApp.support.ZapAlertVulnSupport.TIMING_MARGIN_MS;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sleepMillis;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sleepSecondsWithMargin;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sqliteRandomblobDelayMillis;
import static org.example.vulnApp.support.ZapAlertVulnSupport.sqliteRandomblobBytes;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.regex.Matcher;
import org.example.vulnApp.model.Response;
import org.example.vulnApp.state.VulnAppState;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** SQL injection reproductions grouped by database technology. */
@RestController
public class DatabaseInjectionAlertsController {
    private final VulnAppState state;

    public DatabaseInjectionAlertsController(VulnAppState state) {
        this.state = state;
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionGeneric", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionGeneric(@RequestParam("name") String name) {
        String lower = safeLower(name);
        if (lower.contains("'") || lower.contains("--") || lower.contains(" or ") || lower.contains(" union ")) {
            // Keep this endpoint DB-neutral so rule 40018 can raise the generic SQL Injection alert.
            return text("java.sql.SQLException: syntax error while executing query near '" + name + "'");
        }
        return text("user=" + name);
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionMySqlTimeBased", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionMySqlTimeBased(@RequestParam("name") String name) {
        Matcher m = MYSQL_SLEEP_PATTERN.matcher(name);
        if (m.find()) {
            double seconds = m.group(1) == null ? 5.0 : Double.parseDouble(m.group(1));
            sleepSecondsWithMargin(seconds);
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionHypersonicTimeBased", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionHypersonicTimeBased(@RequestParam("name") String name) {
        Matcher m = HSQL_SLEEP_PATTERN.matcher(name);
        if (m.find()) {
            if (m.group(1) != null || m.group(2) != null) {
                // ZAP 40020 replaces <<<<SLEEP>>>> with milliseconds, for example
                // "java.lang.Thread.sleep"(5000).
                String millis = m.group(1) != null ? m.group(1) : m.group(2);
                sleepMillis((long) Math.min(Double.parseDouble(millis), MAX_SLEEP_SECONDS * 1000.0) + TIMING_MARGIN_MS);
            } else {
                // Compatibility fallback for local/manual CALL SLEEP(seconds) probes.
                sleepSecondsWithMargin(Double.parseDouble(m.group(3)));
            }
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionMsSqlTimeBased", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionMsSqlTimeBased(@RequestParam("name") String name) {
        Matcher m = MSSQL_WAITFOR_PATTERN.matcher(name);
        if (m.find()) {
            sleepSecondsWithMargin(Double.parseDouble(m.group(1)));
        }
        return text("ok");
    }

    // SQL Injection - Oracle - Time Based
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        mediaType = "application/json",
                        schema = @Schema(implementation = Response.class)
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/vulnApp/sqlInjectionOracleTimeBased", method = RequestMethod.GET)
    public ResponseEntity<Response> sqlInjectionOracleTimeBased(@RequestParam(value = "name") String name) {
        final var result = new Response();
        result.test = "<html><body></body></html>";
        if (name == null) {
            return new ResponseEntity<>(result, HttpStatus.OK);
        }
        System.out.println("Oracle SQLi param name = " + name);
        final Matcher oracleSleep = ORACLE_SLEEP_PATTERN.matcher(name);
        if (oracleSleep.find()) {
            final double requestedSeconds = Double.parseDouble(oracleSleep.group(1));
            final double boundedSeconds = Math.min(requestedSeconds, MAX_SLEEP_SECONDS);
            final long sleepMillis = Math.round(boundedSeconds * 1000L) + TIMING_MARGIN_MS;
            System.out.println("Oracle SQLi sleep requested=" + requestedSeconds + "s, actual=" + sleepMillis + "ms");
            sleepMillis(sleepMillis);
        } else if (name.contains("UTL_INADDR.get_host_name(")) {
            sleepMillis(LEGACY_ORACLE_SLEEP_MS);
        }
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    // SQL Injection - PostgreSQL - Time Based
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        mediaType = "application/json",
                        schema = @Schema(implementation = String.class)
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/vulnApp/sqlInjectionPostgres", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionPostgres(@RequestParam(value = "name") String name) {
        var result = "<html><body></body></html>";
        if (name == null) {
            return new ResponseEntity<>(result, HttpStatus.OK);
        }
        if (name.contains("pg_sleep(")) {
            state.payloadSent().add(name);
        }
        final Matcher match = POSTGRES_SLEEP_PATTERN.matcher(name);
        if (!match.find()) {
            return new ResponseEntity<>(name, HttpStatus.OK);
        }
        final double requestedSeconds = Math.min(Double.parseDouble(match.group(1)), MAX_SLEEP_SECONDS);
        sleepMillis(Math.round(requestedSeconds * 1000.0) + 250L);
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    // Original endpoint kept for OpenAPI compatibility.
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        mediaType = "application/json",
                        schema = @Schema(implementation = Response.class)
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/vulnApp/sqlInjectionSqLite", method = RequestMethod.GET)
    public ResponseEntity<Response> sqlInjectionSqLite(@RequestParam(value = "name") String name) {
        final var result = new Response();
        result.test = "<html><body></body></html>";
        if (name == null) {
            return new ResponseEntity<>(result, HttpStatus.OK);
        }
        System.out.println("SQLite SQLi param name = " + name);
        final Matcher randomblob = SQLITE_RANDOMBLOB_PATTERN.matcher(name);
        if (randomblob.find()) {
            final long blobBytes = sqliteRandomblobBytes(randomblob);
            final long sleepMillis = sqliteRandomblobDelayMillis(blobBytes);
            System.out.println("SQLite SQLi randomblob bytes=" + blobBytes + ", sleep=" + sleepMillis + "ms");
            sleepMillis(sleepMillis);
        }
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionSqLiteTimeBased", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionSqLiteTimeBased(@RequestParam("name") String name) {
        Matcher m = SQLITE_RANDOMBLOB_PATTERN.matcher(name);
        if (m.find()) {
            sleepMillis(sqliteRandomblobDelayMillis(sqliteRandomblobBytes(m)));
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/sqlInjectionSqLiteError", method = RequestMethod.GET)
    public ResponseEntity<String> sqlInjectionSqLiteError(@RequestParam("name") String name) {
        if (safeLower(name).contains("randomblob(")) {
            return text("SQL error: no such function: randomblob");
        }
        return text("ok");
    }
}
