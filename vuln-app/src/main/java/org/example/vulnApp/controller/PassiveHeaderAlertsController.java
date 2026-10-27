package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.html;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Passive scan reproductions that depend mostly on response headers/body. */
@RestController
public class PassiveHeaderAlertsController {

    /**
     * Expected passive alerts on a plain Spring Boot app without a security-header filter:
     * - 10020-1 Missing Anti-clickjacking Header
     * - 10021 X-Content-Type-Options Header Missing
     * - 10038-1 Content Security Policy Header Not Set
     *
     * If Spring Security, a reverse proxy, or a global filter injects these headers, ZAP will not raise
     * the missing-header alerts for this response. HSTS 10035-1 additionally requires HTTPS.
     */
    @RequestMapping(value = "/vulnApp/passive/missingSecurityHeaders", method = RequestMethod.GET)
    public ResponseEntity<String> missingSecurityHeaders() {
        return html("<html><head><title>Missing Security Headers</title></head>"
            + "<body><h1>Missing Security Headers</h1>"
            + "<p>This intentionally lacks X-Frame-Options, CSP, X-Content-Type-Options, and HSTS.</p>"
            + "</body></html>");
    }

    /** Expected: 10054-1 Cookie without SameSite Attribute. */
    @RequestMapping(value = "/vulnApp/passive/cookieWithoutSameSite", method = RequestMethod.GET)
    public ResponseEntity<String> cookieWithoutSameSite() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .header("Set-Cookie", "vulnSession=abc123; Path=/; HttpOnly")
            .body("<html><body>Cookie without SameSite</body></html>");
    }

    /** Expected: 10054-2 Cookie with SameSite Attribute None. */
    @RequestMapping(value = "/vulnApp/passive/cookieSameSiteNone", method = RequestMethod.GET)
    public ResponseEntity<String> cookieSameSiteNone() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .header("Set-Cookie", "noneSession=abc123; Path=/; HttpOnly; SameSite=None")
            .body("<html><body>Cookie with SameSite=None</body></html>");
    }

    /** Expected: 10054-3 Cookie with Invalid SameSite Attribute. */
    @RequestMapping(value = "/vulnApp/passive/cookieInvalidSameSite", method = RequestMethod.GET)
    public ResponseEntity<String> cookieInvalidSameSite() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .header("Set-Cookie", "badSameSite=abc123; Path=/; HttpOnly; SameSite=Broken")
            .body("<html><body>Cookie with invalid SameSite</body></html>");
    }

    /**
     * Expected: 10036-1/10036-2 HTTP Server Response Header.
     * Some servlet containers/proxies overwrite or suppress the Server header, so this is environment-dependent.
     */
    @RequestMapping(value = "/vulnApp/passive/serverHeaderLeak", method = RequestMethod.GET)
    public ResponseEntity<String> serverHeaderLeak() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_PLAIN)
            .header("Server", "Apache-Coyote/1.1")
            .body("server header leak");
    }

    /** Expected: 10096 Timestamp Disclosure - Unix. */
    @RequestMapping(value = "/vulnApp/passive/timestampDisclosure", method = RequestMethod.GET)
    public ResponseEntity<String> timestampDisclosure() {
        return json("{\"createdAt\":1704114087,\"updatedAt\":1704114099,\"status\":\"debug\"}");
    }

    /** Expected: 10035-4 Strict-Transport-Security Header on Plain HTTP Response. */
    @RequestMapping(value = "/vulnApp/passive/hstsOnHttp", method = RequestMethod.GET)
    public ResponseEntity<String> hstsOnHttp() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .header("Strict-Transport-Security", "max-age=31536000")
            .body("<html><body>HSTS header deliberately sent over HTTP</body></html>");
    }

    /** Optional baseline endpoint that returns an explicit 500 without X-Content-Type-Options. */
    @RequestMapping(value = "/vulnApp/passive/errorWithoutNosniff", method = RequestMethod.GET)
    public ResponseEntity<String> errorWithoutNosniff() {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .contentType(MediaType.TEXT_HTML)
            .body("<html><body><h1>500 debug page</h1><pre>debug stack trace</pre></body></html>");
    }
}
