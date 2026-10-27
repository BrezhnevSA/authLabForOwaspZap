package org.example.vulnApp.controller;

import io.swagger.v3.oas.annotations.Hidden;
import org.example.vulnApp.state.VulnAppState;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Non-vulnerability utility endpoints for navigation and test-state reset. */
@RestController
public class AppUtilityController {
    private final VulnAppState state;

    public AppUtilityController(VulnAppState state) {
        this.state = state;
    }

    @Hidden
    @RequestMapping(value = {"/", "/vulnApp"}, method = RequestMethod.GET)
    public ResponseEntity<String> index() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(
                "<!doctype html><html><head><meta charset='UTF-8'><title>vulnApp XXE</title></head><body>"
                    + "<h1>vulnApp XXE test</h1>"
                    + "<p><a id='xxeFixtureLink' href='/app/vulnApp/xxeBrowserFixture'>Open XXE browser fixture</a></p>"
                    + "<p><a href=\"/app/vulnApp/prototypePollution?key=__proto__&amp;prop=headers&amp;value=ptk-polluted\">Prototype pollution lab</a></p>"
                    + "</body></html>"
            );
    }

    @Hidden
    @RequestMapping(value = "/vulnApp/xxeBrowserFixture", method = RequestMethod.GET)
    public ResponseEntity<String> xxeBrowserFixture() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(
                "<!doctype html><html><head><meta charset='UTF-8'><title>XXE test</title></head><body>"
                    + "<h1>XXE XML test</h1>"
                    + "<p>This page intentionally sends an XML request so ZAP AJAX Spider records "
                    + "an application/xml POST for active scan rule 90023.</p>"
                    + "<form id='xxeForm'>"
                    + "<label for='xmlPayload'>XML payload</label><br>"
                    + "<textarea id='xmlPayload' rows='8' cols='90'>&lt;?xml version=&quot;1.0&quot;?&gt;&lt;foo&gt;baseline&lt;/foo&gt;</textarea><br>"
                    + "<button id='sendXxe' type='submit'>Send XML</button>"
                    + "</form>"
                    + "<h2>Response</h2><pre id='status'>Waiting...</pre>"
                    + "<script>"
                    + "(function(){"
                    + "var form=document.getElementById('xxeForm');"
                    + "var payload=document.getElementById('xmlPayload');"
                    + "var status=document.getElementById('status');"
                    + "function sendXml(){"
                    + "status.textContent='Sending application/xml POST...';"
                    + "return fetch('xxeBrowserSeed',{method:'POST',"
                    + "headers:{'Content-Type':'application/xml','Accept':'text/plain'},"
                    + "body:payload.value,credentials:'same-origin'})"
                    + ".then(function(r){return r.text().then(function(t){"
                    + "status.textContent='HTTP '+r.status+'\\n'+t;return r;});})"
                    + ".catch(function(e){status.textContent='Request failed: '+e;});"
                    + "}"
                    + "form.addEventListener('submit',function(e){e.preventDefault();sendXml();});"
                    + "window.addEventListener('load',function(){setTimeout(sendXml,250);});"
                    + "})();"
                    + "</script>"
                    + "</body></html>"
            );
    }

    @Hidden
    @RequestMapping(value = "/clearData", method = RequestMethod.GET)
    public ResponseEntity<Void> clearData() {
        state.clear();
        return ResponseEntity.ok().build();
    }
}
