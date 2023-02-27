
package com.baeldung.openapi.config;

import javax.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@SecurityScheme(name = "Bearer Authentication", type = SecuritySchemeType.HTTP, bearerFormat = "JWT", scheme = "bearer")
public class ProjectSecurityConfig {
	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().cors()
				.configurationSource(new CorsConfigurationSource() {

					@Override
					public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
						CorsConfiguration config = new CorsConfiguration();
						config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
						config.setAllowedMethods(Collections.singletonList("*"));
						config.setAllowCredentials(true);
						config.setAllowedHeaders(Collections.singletonList("*"));
						config.setExposedHeaders(Arrays.asList("Authorization"));
						config.setMaxAge(3600L);
						return config;
					}
				}).and().csrf().ignoringAntMatchers("/contact", "/register")
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and().authorizeHttpRequests()
				.antMatchers("/myAccount").hasRole("USER").antMatchers("/cities").hasAnyRole("USER", "ADMIN")
				.antMatchers("/myLoans").authenticated().antMatchers("/myCards").hasRole("USER").antMatchers("/user")
				.authenticated().antMatchers("/notices", "/contact", "/register").permitAll().and()
				.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwtAuthenticationConverter);
		return http.build();
	}

}
