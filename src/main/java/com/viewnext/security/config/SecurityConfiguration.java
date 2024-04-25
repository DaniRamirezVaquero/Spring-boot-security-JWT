package com.viewnext.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

  private final JwtAuthenticantionFilter jwtAuthFilter;
  private final AuthenticationProvider authenticationProvider;

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
      http
              .csrf(csrf -> csrf.disable())
              .authorizeHttpRequests(requests -> {
                try {
                  requests
                                  .requestMatchers("/api/v1/auth/**")
                                  .permitAll()
                                  .anyRequest().authenticated()
                                  .and()
                                  .sessionManagement(management -> management
                                          .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                  .authenticationProvider(authenticationProvider)
                                  .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
                } catch (Exception e) {
                  e.printStackTrace();
                }
              }
              );
                      

    return http.build();
  }
}
