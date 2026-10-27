package org.example.vulnApp.controller;

import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import java.util.stream.Collectors;
import org.example.vulnApp.model.Response;
import org.example.vulnApp.model.SomeObject;
import org.example.vulnApp.state.VulnAppState;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Reflected, stored and DOM-oriented XSS reproductions. */
@RestController
public class XssAlertsController {
    private final VulnAppState state;

    public XssAlertsController(VulnAppState state) {
        this.state = state;
    }

    // Cross Site Scripting Weakness (Persistent in JSON Response)
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
    @RequestMapping(value = "/comment", method = RequestMethod.POST)
    public ResponseEntity<String> addComment(@RequestParam String value) {
        SomeObject comment = new SomeObject();
        comment.id = (long) state.commentRepository().size();
        comment.value = value;
        state.commentRepository().add(comment);
        return new ResponseEntity<>("{\"value\":\"" + comment.value + "\",id:" + comment.id + "}", HttpStatus.OK);
    }

    // Cross Site Scripting Weakness (Persistent in JSON Response)
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        array = @ArraySchema(schema = @Schema(implementation = String.class))
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/comment", method = RequestMethod.GET)
    public ResponseEntity<List<String>> getComments() {
        return new ResponseEntity<>(
            state.commentRepository().stream()
                .map(comment -> "{\"value\":\"" + comment.value + "\",id:" + comment.id + "}")
                .collect(Collectors.toList()),
            HttpStatus.OK
        );
    }

    // Cross Site Scripting Weakness (Persistent in JSON Response)
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        array = @ArraySchema(schema = @Schema(implementation = String.class))
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/comment/{id}", method = RequestMethod.GET)
    public ResponseEntity<List<String>> getComment(@PathVariable("id") Long id) {
        return new ResponseEntity<>(
            state.commentRepository().stream()
                .filter(comment -> comment.id.equals(id))
                .map(comment -> "{\"value\":\"" + comment.value + "\",id:" + comment.id + "}")
                .collect(Collectors.toList()),
            HttpStatus.OK
        );
    }

    // Cross Site Scripting Weakness (Persistent in HTML Response)
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
    @RequestMapping(value = "/comment/html", method = RequestMethod.GET)
    public ResponseEntity<String> getCommentsHtml() {
        return new ResponseEntity<>(
            "<html><body>"
                + state.commentRepository().stream()
                .map(comment -> "<p>" + comment.value + " with id:" + comment.id + "</p>")
                .collect(Collectors.toList())
                + "</body></html>",
            HttpStatus.OK
        );
    }

    // Cross Site Scripting (Persistent)
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
    @RequestMapping(value = "/event", method = RequestMethod.POST)
    public ResponseEntity<String> addEvent(@RequestParam String value) {
        SomeObject event = new SomeObject();
        event.id = (long) state.eventRepository().size();
        event.value = value;
        state.eventRepository().add(event);
        return new ResponseEntity<>("{\"id\":" + event.id + "}", HttpStatus.OK);
    }

    // Cross Site Scripting (Persistent)
    @ApiResponses(
        value = {
            @ApiResponse(
                content = {
                    @Content(
                        mediaType = MediaType.TEXT_HTML_VALUE,
                        schema = @Schema(implementation = String.class)
                    )
                }
            )
        }
    )
    @RequestMapping(value = "/event", method = RequestMethod.GET)
    public ResponseEntity<String> getEvents() {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body(
                "<html><body>"
                    + state.eventRepository().stream()
                    .map(event -> "<p>" + event.value + " with id:" + event.id + "</p>")
                    .collect(Collectors.joining())
                    + "</body></html>"
            );
    }

    // Cross Site Scripting Weakness (Reflected in JSON Response)
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
    @RequestMapping(value = "/vulnApp/cssw", method = RequestMethod.GET)
    public ResponseEntity<Response> csswVuln(@RequestParam(value = "name") String name) {
        final var result = new Response();
        result.test = "<tr><td>Hello " + name + " !</tr></td>\\n";
        return new ResponseEntity<>(result, HttpStatus.OK);
    }

    // Cross Site Scripting (DOM Based) / Cross Site Scripting (Reflected)
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
    @RequestMapping(value = "/vulnApp/cssw/html", method = RequestMethod.GET)
    public ResponseEntity<String> csswVulnHtml(@RequestParam(value = "name") String name) {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body("<!doctype html><html><body><div id='name'>Hello " + name + " !</div></body></html>");
    }

    /**
     * Expected at LOW threshold for rule 40012: Cross Site Scripting Weakness
     * (Reflected in JSON Response).
     */
    @RequestMapping(value = "/vulnApp/reflectedXssJson", method = RequestMethod.GET)
    public ResponseEntity<String> reflectedXssJson(@RequestParam(value = "name") String name) {
        // Match the shape used by ZAP's own CrossSiteScriptingScanRule JSON unit test:
        // reflect the tainted value as a plain JSON string value, not inside HTML markup.
        // The dedicated JSON alert is emitted only when rule 40012 uses threshold LOW.
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_JSON)
            .body("{ \"name\":\"" + name + "\", \"age\":30, \"car\":null }");
    }


    /**
     * Expected: 40026 Cross Site Scripting (DOM Based).
     * Requires the DOM XSS add-on, Selenium/browser support, and the 40026 rule enabled.
     */
    @RequestMapping(value = "/vulnApp/domXss", method = RequestMethod.GET)
    public ResponseEntity<String> domXss(@RequestParam(value = "name", required = false) String name) {
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_HTML)
            .body("<html><head><title>DOM XSS</title></head>"
                + "<body><h1>DOM XSS lab</h1><div id='result'></div>"
                + "<script>"
                + "const p=new URLSearchParams(window.location.search);"
                + "const value=p.get('name') || window.location.hash.substring(1) || '';"
                + "document.getElementById('result').innerHTML=value;"
                + "</script></body></html>");
    }

}
