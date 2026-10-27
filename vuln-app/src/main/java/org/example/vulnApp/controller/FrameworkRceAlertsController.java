package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.text;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Framework-specific RCE reproductions which are detected by response behavior, not by real RCE. */
@RestController
public class FrameworkRceAlertsController {

    /**
     * Expected: 40045 Spring4Shell.
     * ZAP confirms this rule when the Spring4Shell payload gets HTTP 400 but a safe payload does not.
     */
    @RequestMapping(value = "/vulnApp/spring4shell", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<String> spring4Shell(@RequestParam Map<String, String> params) {
        String value = params.get("class.module.classLoader.DefaultAssertionStatus");
        if ("nonsense".equals(value)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .contentType(MediaType.TEXT_PLAIN)
                .body("Bad Request");
        }
        return text("spring4shell baseline ok");
    }

    /**
     * Expected: 40048 Remote Code Execution (React2Shell).
     * ZAP sends a POST multipart request with Next-Action and expects HTTP 500 plus evidence E{\"digest\".
     */
    @RequestMapping(value = "/vulnApp/react2shell", method = RequestMethod.POST, consumes = MediaType.ALL_VALUE)
    public ResponseEntity<String> react2Shell(
        @RequestHeader(value = "Next-Action", required = false) String nextAction,
        @RequestHeader(value = "Next-Router-State-Tree", required = false) String nextRouterStateTree,
        @RequestBody(required = false) byte[] body
    ) {
        String requestBody = body == null ? "" : new String(body, StandardCharsets.UTF_8);
        if (nextAction != null
            && nextRouterStateTree != null
            && requestBody.contains("[\"$1:a:a\"]")) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.TEXT_PLAIN)
                .body("E{\"digest\":\"vulnapp-react2shell-lab\"}");
        }
        return text("react2shell baseline ok");
    }
}
