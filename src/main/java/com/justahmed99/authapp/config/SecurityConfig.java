package com.justahmed99.authapp.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    return httpSecurity
        .csrf(AbstractHttpConfigurer::disable)
        .cors(AbstractHttpConfigurer::disable)
        .sessionManagement(Customizer.withDefaults())
        .exceptionHandling(
            exceptionHandlingConfigurer -> exceptionHandlingConfigurer.authenticationEntryPoint(
                authenticationEntryPoint()))
        .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
            authorizationManagerRequestMatcherRegistry
                .requestMatchers("/oauth2/**", "/login/**").permitAll()
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/regular/**").hasRole("REGULAR")
                .anyRequest().authenticated())
        .oauth2Client(Customizer.withDefaults())
        .oauth2Login(Customizer.withDefaults())
        .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(
            jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
        .logout(Customizer.withDefaults())
        .build();
  }

  @Bean
  public AuthenticationEntryPoint authenticationEntryPoint() {
    return new HttpStatusEntryPoint(HttpStatus.FORBIDDEN);
  }

  @SuppressWarnings("unchecked")
  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();

    jwtConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
      Map<String, Object> claims = jwt.getClaims();
      Map<String, Object> realmAccess = (Map<String, Object>) claims.get("realm_access");
      if (realmAccess == null) {
        return new ArrayList<>();
      }

      List<String> roles = (List<String>) realmAccess.get("roles");
      if (roles == null) {
        return new ArrayList<>();
      }

      List<GrantedAuthority> authorities = roles.stream()
          .map(roleName -> "ROLE_" + roleName.toUpperCase())
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toList());

      System.out.println("Extracted Authorities: " + authorities);

      return authorities;
    });

    return jwtConverter;
  }
}
