package testbed.springform;

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
import org.springframework.web.bind.annotation.ResponseBody;
import java.util.Map;

@SpringBootApplication
public class Application {
  public static void main(String[] args) { SpringApplication.run(Application.class, args); }

  @Bean
  UserDetailsService users() {
    return new InMemoryUserDetailsManager(User.withUsername("zapuser").password("{noop}ZapTest123!").roles("USER").build());
  }

  @Bean
  SecurityFilterChain security(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(a -> a
        .requestMatchers("/login", "/api/whoami").permitAll()
        .anyRequest().authenticated())
      .formLogin(f -> f.loginPage("/login").defaultSuccessUrl("/private", true).permitAll())
      .logout(l -> l.logoutSuccessUrl("/login?logout"));
    return http.build();
  }

  @Controller
  static class Routes {
    @GetMapping("/login") String login() { return "login"; }
    @GetMapping("/private") String privatePage(Model model) { model.addAttribute("technology", "SPRING_BOOT"); return "private"; }
    @GetMapping("/api/whoami") @ResponseBody Map<String,Object> whoami(org.springframework.security.core.Authentication auth) {
      boolean ok = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName());
      return ok ? Map.of("authenticated", true, "username", auth.getName(), "technology", "SPRING_BOOT") : Map.of("authenticated", false, "technology", "SPRING_BOOT");
    }
  }
}
