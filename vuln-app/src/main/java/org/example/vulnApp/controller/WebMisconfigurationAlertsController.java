package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.VALID_PADDING_ORACLE_TOKEN_HEX;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.net.URI;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Web misconfiguration and generic input-handling reproductions. */
@RestController
public class WebMisconfigurationAlertsController {

    @RequestMapping(value = "/vulnApp/externalRedirect", method = RequestMethod.GET)
    public ResponseEntity<Void> externalRedirect(@RequestParam("url") String url) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(url)).build();
    }

    @RequestMapping(value = "/vulnApp/cors", method = {RequestMethod.GET, RequestMethod.OPTIONS})
    public ResponseEntity<String> cors(@RequestHeader(value = "Origin", required = false) String origin) {
        String allowOrigin = origin == null ? "*" : origin;
        return ResponseEntity.ok()
            .header("Access-Control-Allow-Origin", allowOrigin)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            .header("Access-Control-Allow-Headers", "*")
            .body("cors-ok");
    }

    @RequestMapping(value = "/vulnApp/parameterTampering", method = RequestMethod.GET)
    public ResponseEntity<String> parameterTampering(@RequestParam(value = "price", required = false) String price) {
        String value = price == null ? "" : price;
        if (value.isBlank() || "@".equals(value) || "+".equals(value) || "|".equals(value) || value.indexOf('\0') >= 0) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.TEXT_PLAIN)
                .body("javax.servlet.ServletException: invoke exception while parsing price");
        }
        return json("{\"acceptedPrice\":" + value.replaceAll("[^0-9.-]", "") + ",\"status\":\"order-created\"}");
    }

    @RequestMapping(value = "/vulnApp/bufferOverflow", method = RequestMethod.GET)
    public ResponseEntity<String> bufferOverflow(@RequestParam("input") String input) {
        // ZAP 30001 sends a 2100-character random string and requires HTTP 500 plus Connection: close.
        if (input.length() >= 2100) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .header("Connection", "close")
                .contentType(MediaType.TEXT_PLAIN)
                .body("Segmentation fault (core dumped)");
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/formatString", method = RequestMethod.GET)
    public ResponseEntity<String> formatString(@RequestParam("input") String input) {
        if (input.contains("%x") || input.contains("%s") || input.contains("%n")) {
            return text("41414141 42424242 7ffeefbff5c0 " + input);
        }
        return text("ok");
    }

    @RequestMapping(value = "/vulnApp/ssrf", method = RequestMethod.GET)
    public ResponseEntity<String> ssrf(@RequestParam("url") String url) {
        String lower = safeLower(url);
        if (lower.contains("169.254.169.254") || lower.contains("metadata.google.internal") || lower.contains("metadata/instance")) {
            return json("{\"instanceId\":\"i-1234567890abcdef0\",\"iam\":\"admin-role\"}");
        }
        return text("fetched " + url);
    }

    @RequestMapping(value = {"/latest/meta-data", "/latest/meta-data/"}, method = RequestMethod.GET)
    public ResponseEntity<String> awsMetadata() {
        return text("ami-id\ninstance-id\nlocal-hostname\npublic-hostname\n");
    }

    @RequestMapping(value = {"/computeMetadata/v1", "/computeMetadata/v1/"}, method = RequestMethod.GET)
    public ResponseEntity<String> gcpMetadata() {
        return text("project-id\nzone\nmachineType\nhostname\n");
    }

    @RequestMapping(value = "/vulnApp/paddingOracle", method = RequestMethod.GET)
    public ResponseEntity<String> paddingOracle(
        @Parameter(schema = @Schema(example = VALID_PADDING_ORACLE_TOKEN_HEX))
        @RequestParam("token") String token
    ) {
        if (token == null || token.isBlank()) {
            return text("empty token accepted");
        }
        if (VALID_PADDING_ORACLE_TOKEN_HEX.equalsIgnoreCase(token)) {
            return text("token accepted");
        }
        if (looksLikeEncodedOracleCandidate(token)) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.TEXT_PLAIN)
                .body("javax.crypto.BadPaddingException: Given final block not properly padded");
        }
        return text("token accepted");
    }

    @RequestMapping(value = "/vulnApp/insecureMethod", method = {RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.TRACE})
    public ResponseEntity<String> insecureMethod() {
        return text("method accepted");
    }

    private boolean looksLikeEncodedOracleCandidate(String token) {
        return token.matches("(?i)^[a-f0-9]{32,}$")
            || token.matches("^[a-zA-Z0-9/+]+={0,2}$")
            || token.matches("^[a-zA-Z0-9_-]+[012]$");
    }
}
