package testbed.springform;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@SpringBootApplication
public class Application {
  static final String CONTROL_TOKEN = "zap-testbed-reset-v1";
  static final List<String> EXPECTED = List.of("/private");
  static final Set<String> HITS = ConcurrentHashMap.newKeySet();
  static final AtomicInteger LOGIN_ATTEMPTS = new AtomicInteger();
  static final AtomicInteger SUCCESSFUL_LOGINS = new AtomicInteger();
  static final AtomicInteger FAILED_LOGINS = new AtomicInteger();
  static final AtomicInteger AUTHENTICATED_REQUESTS = new AtomicInteger();
  static final AtomicInteger UNAUTHORIZED_REQUESTS = new AtomicInteger();

  public static void main(String[] args) { SpringApplication.run(Application.class, args); }

  @Bean
  UserDetailsService users() {
    return new InMemoryUserDetailsManager(User.withUsername("zapuser").password("{noop}ZapTest123!").roles("USER").build());
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http) throws Exception {
    http.csrf(csrf -> csrf.ignoringRequestMatchers("/__testbed/**"))
      .authorizeHttpRequests(a -> a
        .requestMatchers("/login", "/api/whoami", "/__testbed/**").permitAll()
        .anyRequest().authenticated())
      .formLogin(f -> f.loginPage("/login").defaultSuccessUrl("/private", true)
          .successHandler((request,response,authentication)->{
            LOGIN_ATTEMPTS.incrementAndGet(); SUCCESSFUL_LOGINS.incrementAndGet(); response.sendRedirect("/private");
          })
          .failureHandler((request,response,exception)->{
            LOGIN_ATTEMPTS.incrementAndGet(); FAILED_LOGINS.incrementAndGet(); response.sendRedirect("/login?error");
          }).permitAll())
      .logout(l -> l.logoutSuccessUrl("/login?logout"));
    return http.build();
  }

  static Map<String,Object> coverage() {
    var visited = EXPECTED.stream().filter(HITS::contains).toList();
    var missing = EXPECTED.stream().filter(p -> !HITS.contains(p)).toList();
    return Map.of(
      "application", "spring-form",
      "scenario", "form-cookie",
      "discovery", Map.of(
        "expected", EXPECTED.size(), "visited", visited.size(),
        "coveragePercent", EXPECTED.isEmpty() ? 100.0 : visited.size() * 100.0 / EXPECTED.size(),
        "visitedEndpoints", visited, "missingEndpoints", missing),
      "authentication", Map.of(
        "loginAttempts", LOGIN_ATTEMPTS.get(), "successfulLogins", SUCCESSFUL_LOGINS.get(),
        "failedLogins", FAILED_LOGINS.get(), "authenticatedRequests", AUTHENTICATED_REQUESTS.get(),
        "unauthorizedRequests", UNAUTHORIZED_REQUESTS.get()));
  }

  @Controller
  static class Routes {
    @GetMapping("/login") String login() { return "login"; }

    @GetMapping("/private") String privatePage(Model model, org.springframework.security.core.Authentication auth) {
      HITS.add("/private");
      if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) AUTHENTICATED_REQUESTS.incrementAndGet();
      else UNAUTHORIZED_REQUESTS.incrementAndGet();
      model.addAttribute("technology", "SPRING_BOOT"); return "private";
    }

    @GetMapping("/api/whoami") @ResponseBody Map<String,Object> whoami(org.springframework.security.core.Authentication auth) {
      boolean ok = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName());
      if (ok) AUTHENTICATED_REQUESTS.incrementAndGet(); else UNAUTHORIZED_REQUESTS.incrementAndGet();
      return ok ? Map.of("authenticated", true, "username", auth.getName(), "technology", "SPRING_BOOT") : Map.of("authenticated", false, "technology", "SPRING_BOOT");
    }

    @GetMapping("/__testbed/expected") @ResponseBody Map<String,Object> expected() {
      return Map.of("application", "spring-form", "expectedEndpoints", EXPECTED);
    }

    @GetMapping("/__testbed/coverage") @ResponseBody Map<String,Object> coverageEndpoint() { return coverage(); }

    @PostMapping("/__testbed/control/reset") @ResponseBody Object reset(HttpServletRequest request, jakarta.servlet.http.HttpServletResponse response) {
      if (!CONTROL_TOKEN.equals(request.getHeader("X-Testbed-Control"))) {
        response.setStatus(404); return Map.of("error", "not found");
      }
      HITS.clear(); LOGIN_ATTEMPTS.set(0); SUCCESSFUL_LOGINS.set(0); FAILED_LOGINS.set(0); AUTHENTICATED_REQUESTS.set(0); UNAUTHORIZED_REQUESTS.set(0);
      return Map.of("reset", true, "application", "spring-form");
    }
  }
}
