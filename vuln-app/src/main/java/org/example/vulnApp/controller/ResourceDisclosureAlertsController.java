package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.html;
import static org.example.vulnApp.support.ZapAlertVulnSupport.json;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;
import static org.example.vulnApp.support.ZapAlertVulnSupport.xml;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import org.example.vulnApp.model.Response;
import org.example.vulnApp.model.SomeObject;
import org.example.vulnApp.state.VulnAppState;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Resource, hidden-file, debug and application-error disclosure reproductions. */
@RestController
public class ResourceDisclosureAlertsController {
    private final VulnAppState state;

    public ResourceDisclosureAlertsController(VulnAppState state) {
        this.state = state;
    }

    // Information Disclosure - Debug Error Messages / Application Error Disclosure
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
    @RequestMapping(value = "/issue", method = RequestMethod.POST)
    public SomeObject addIssue(@RequestParam String value) {
        SomeObject issue = new SomeObject();
        issue.id = (long) state.eventRepository().size();
        issue.value = value;
        state.issueRepository().add(issue);
        return issue;
    }

    // Information Disclosure - Debug Error Messages / Application Error Disclosure
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        array = @ArraySchema(schema = @Schema(implementation = Response.class))
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/issue", method = RequestMethod.GET)
    public List<SomeObject> getIssues() {
        return state.commentRepository();
    }

    // Hidden File Found
    @Hidden
    @RequestMapping(value = {"/CVS/root", "/CVS/Root", "/vulnApp/CVS/root", "/vulnApp/CVS/Root"}, method = RequestMethod.GET)
    public ResponseEntity<String> hiddenCvsRoot() {
        return text(":pserver:build-user@source.internal:/srv/vuln-app");
    }

    /**
     * HiddenFilesScanRule always checks these built-in fallback names even when
     * ZAP's json/hidden_files.json was not installed/extracted with the add-on.
     */
    @Hidden
    @RequestMapping(
        value = {
            "/.hg", "/vulnApp/.hg",
            "/.bzr", "/vulnApp/.bzr",
            "/._darcs", "/vulnApp/._darcs",
            "/BitKeeper", "/vulnApp/BitKeeper"
        },
        method = RequestMethod.GET
    )
    public ResponseEntity<String> hiddenFileFallback() {
        return text("vulnApp hidden repository metadata - intentionally exposed");
    }

    @RequestMapping(value = {"/.env", "/vulnApp/.env"}, method = RequestMethod.GET)
    public ResponseEntity<String> envLeak() {
        return text("DB_PASSWORD=secret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSPRING_PROFILES_ACTIVE=prod");
    }

    @RequestMapping(value = {"/.htaccess", "/vulnApp/.htaccess"}, method = RequestMethod.GET)
    public ResponseEntity<String> htaccessLeak() {
        return text("AuthType Basic\nAuthName \"Restricted\"\nAuthUserFile /var/www/.htpasswd\nRequire valid-user");
    }

    @RequestMapping(value = {"/.git/config", "/vulnApp/.git/config"}, method = RequestMethod.GET)
    public ResponseEntity<String> gitConfigLeak() {
        return text("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:example/private.git");
    }



    @Hidden
    @RequestMapping(value = {"/.git/HEAD", "/vulnApp/.git/HEAD"}, method = RequestMethod.GET)
    public ResponseEntity<String> gitHeadLeak() {
        return text("ref: refs/heads/main\n");
    }

    @Hidden
    @RequestMapping(value = {"/.svn/entries", "/vulnApp/.svn/entries"}, method = RequestMethod.GET)
    public ResponseEntity<String> svnEntriesLeak() {
        return text("10\ndir\n\nhttps://svn.example.internal/repos/vulnApp\n");
    }

    @RequestMapping(value = {"/WEB-INF/web.xml", "/vulnApp/WEB-INF/web.xml"}, method = RequestMethod.GET)
    public ResponseEntity<String> webInfLeak() {
        return xml("<web-app><display-name>vuln-app</display-name><servlet><servlet-name>secret</servlet-name></servlet></web-app>");
    }

    @RequestMapping(value = {"/elmah.axd", "/vulnApp/elmah.axd"}, method = RequestMethod.GET)
    public ResponseEntity<String> elmahLeak() {
        return html("<html><title>Error Log for /</title><body><h1>ELMAH Error Log</h1><table><tr><td>System.Exception</td></tr></table></body></html>");
    }

    @RequestMapping(value = {"/trace.axd", "/vulnApp/trace.axd"}, method = RequestMethod.GET)
    public ResponseEntity<String> traceAxdLeak() {
        return html("<html><title>Application Trace</title><body><h1>Trace Information</h1><table><tr><td>Session Id</td><td>ASP.NET</td></tr></table></body></html>");
    }

    @RequestMapping(value = {"/actuator/env", "/vulnApp/actuator/env"}, method = RequestMethod.GET)
    public ResponseEntity<String> actuatorEnv() {
        return json("{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"systemEnvironment\",\"properties\":{\"DB_PASSWORD\":{\"value\":\"secret\"}}}]}");
    }

    @RequestMapping(value = {"/actuator/heapdump", "/vulnApp/actuator/heapdump"}, method = RequestMethod.GET)
    public ResponseEntity<String> actuatorHeapdump() {
        return ResponseEntity.status(HttpStatus.OK)
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .body("JAVA PROFILE 1.0.2\u0000heapdump-secret-password");
    }
}
