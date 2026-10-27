package org.example.vulnApp.controller;

import static org.example.vulnApp.support.ZapAlertVulnSupport.escapeXml;
import static org.example.vulnApp.support.ZapAlertVulnSupport.safeLower;
import static org.example.vulnApp.support.ZapAlertVulnSupport.text;
import static org.example.vulnApp.support.ZapAlertVulnSupport.xml;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.media.Content;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** XML-family alerts: XPath, XXE, and XSLT injection. */
@RestController
public class XmlInjectionAlertsController {
    private static final Pattern ZAP_REMOTE_XXE_PATTERN = Pattern.compile(
        "(?is)<!ENTITY\\s+zapxxe\\s+SYSTEM\\s+\"(https?://[^\"]+)\""
    );


    @RequestMapping(value = "/vulnApp/xpathInjection", method = RequestMethod.GET)
    public ResponseEntity<String> xpathInjection(@RequestParam("name") String name) {
        String lower = safeLower(name);
        if (lower.contains(" or ") || lower.contains("'1'='1") || lower.contains("\"1\"=\"1")) {
            return xml("<users><user>admin</user><user>guest</user><user>zap</user></users>");
        }
        if (name.contains("'") || name.contains("\"")) {
            return xml("<error>XPathExpressionException: invalid predicate near " + escapeXml(name) + "</error>");
        }
        return xml("<users><user>" + escapeXml(name) + "</user></users>");
    }

    @RequestMapping(value = "/vulnApp/xxe", method = RequestMethod.POST, consumes = MediaType.APPLICATION_XML_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> xxe(
        @io.swagger.v3.oas.annotations.parameters.RequestBody(
            required = true,
            content = @Content(
                mediaType = MediaType.APPLICATION_XML_VALUE,
                schema = @Schema(type = "string", example = "<?xml version=\"1.0\"?><foo>baseline</foo>")
            )
        )
        @RequestBody String body
    ) {
        return processXxe(body);
    }

    /**
     * Browser-only seed for ZAP's XXE active scan rule. This endpoint is deliberately hidden from
     * OpenAPI so the first Sites-tree message for it is the browser POST with application/xml.
     */
    @Hidden
    @RequestMapping(
        value = "/vulnApp/xxeBrowserSeed",
        method = RequestMethod.POST,
        consumes = MediaType.APPLICATION_XML_VALUE,
        produces = MediaType.TEXT_PLAIN_VALUE
    )
    public ResponseEntity<String> xxeBrowserSeed(@RequestBody String body) {
        return processXxe(body);
    }

    private ResponseEntity<String> processXxe(String body) {
        String lower = safeLower(body);

        // ZAP 90023 performs remote/OAST XXE checks even at LOW attack strength.
        // Emulate a vulnerable XML parser by dereferencing only the specific `zapxxe`
        // external entity used by the rule. This makes the OAST callback observable by ZAP.
        Matcher remoteEntity = ZAP_REMOTE_XXE_PATTERN.matcher(body);
        if (remoteEntity.find()) {
            triggerZapXxeCallback(remoteEntity.group(1));
            return text("zapxxe remote entity requested");
        }

        // MEDIUM+ uses local-file reflection. Return the exact Unix passwd evidence expected
        // by XxeScanRule when it substitutes file:///etc/passwd into the XML body.
        if (lower.contains("<!doctype")
            || lower.contains("<!entity")
            || lower.contains("&zapxxe;")
            || lower.contains("file:///etc/passwd")
            || lower.contains("system \"file:///")
            || lower.contains("system 'file:///")) {
            return text("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin");
        }
        return xml("<ok>true</ok>");
    }

    private static void triggerZapXxeCallback(String callbackUrl) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(callbackUrl).openConnection();
            connection.setConnectTimeout(3000);
            connection.setReadTimeout(3000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestMethod("GET");
            try (InputStream input = connection.getInputStream()) {
                byte[] buffer = new byte[256];
                while (input.read(buffer) != -1) {
                    // Consume the small callback response so the request completes.
                }
            }
        } catch (Exception ignored) {
            // The local-reflection branch still covers MEDIUM+ scans if OAST is unreachable.
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    // XSLT Injection
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        mediaType = MediaType.TEXT_PLAIN_VALUE,
                        schema = @Schema(implementation = String.class)
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/vulnApp/xsltInjection", method = RequestMethod.GET)
    public ResponseEntity<String> xsltInjection(@RequestParam(value = "template") String template) {
        if (template != null && template.trim().startsWith("<")
            && !template.contains("system-property")
            && !template.contains("runtime:getRuntime()")
            && !template.contains("php:function")) {
            return ResponseEntity.ok("XSLT compile error: SAXParseException");
        }
        if (template.contains("system-property('xsl:vendor')")) {
            return ResponseEntity.ok("Apache Xalan");
        }
        if (template.contains("runtime:getRuntime()") || template.contains("php:function('exec'")) {
            return ResponseEntity.ok("Cannot run program erroneous_command");
        }
        if (template.contains("document('http://")) {
            return ResponseEntity.ok("Connection Refused");
        }
        return ResponseEntity.ok("Transformation completed");
    }
}
