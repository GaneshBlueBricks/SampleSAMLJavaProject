package com.samlexample.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/**", "/login","/acs","/dashboard").permitAll() // Allow access to home and login
                .anyRequest().authenticated() // All other requests require authentication
            )
            .csrf(csrf -> csrf.disable()) // Disable CSRF protection for simplicity (for testing purposes)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            )
            .logout(logout -> logout
                .permitAll()
            )
            .formLogin().disable(); // Disable default form login to avoid conflict with your custom login
        return http.build();
    }

}