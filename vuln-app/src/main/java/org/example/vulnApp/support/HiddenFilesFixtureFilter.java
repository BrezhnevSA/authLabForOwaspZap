package org.example.vulnApp.support;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Makes repository metadata fixtures available at any URL depth.
 *
 * <p>ZAP's Hidden File Finder (40035) derives probe paths from the Active Scan base message.
 * Depending on which node becomes the base message it can request, for example,
 * {@code /app/.git/config}, {@code /app/vulnApp/.git/config}, or
 * {@code /app/vulnApp/10/.git/config}. The fixture therefore matches exact hidden-file suffixes
 * instead of exposing them only at a fixed controller path.
 *
 * <p>Unknown paths are deliberately passed through untouched, so ZAP's random control requests
 * such as {@code .../zap123} and {@code .../.zap456} still receive the application's normal 404.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class HiddenFilesFixtureFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        if (!"GET".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();

        if (path.endsWith("/.git/config")) {
            writeText(
                response,
                "[core]\n"
                    + "repositoryformatversion = 0\n"
                    + "[remote \"origin\"]\n"
                    + "url = git@github.com:example/private.git\n"
            );
            return;
        }

        if (path.endsWith("/.git/HEAD")) {
            writeText(response, "ref: refs/heads/main\n");
            return;
        }

        if (path.endsWith("/CVS/root") || path.endsWith("/CVS/Root")) {
            writeText(response, ":pserver:build-user@source.internal:/srv/vuln-app\n");
            return;
        }

        if (path.endsWith("/.hg")) {
            writeText(response, "vulnApp mercurial metadata\n");
            return;
        }

        if (path.endsWith("/.bzr")) {
            writeText(response, "vulnApp bazaar metadata\n");
            return;
        }

        if (path.endsWith("/._darcs")) {
            writeText(response, "vulnApp darcs metadata\n");
            return;
        }

        if (path.endsWith("/BitKeeper")) {
            writeText(response, "vulnApp bitkeeper metadata\n");
            return;
        }

        if (path.endsWith("/.svn/entries")) {
            writeText(response, "10\ndir\n\nhttps://svn.example.internal/repos/vulnApp\n");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private static void writeText(HttpServletResponse response, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
    }
}
