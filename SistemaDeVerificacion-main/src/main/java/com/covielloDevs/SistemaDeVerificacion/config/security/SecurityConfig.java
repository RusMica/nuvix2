package com.covielloDevs.SistemaDeVerificacion.config.security;

import com.covielloDevs.SistemaDeVerificacion.services.security.UserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsService userDetailsService;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, UserDetailsService userDetailsService) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth
                            // Permitir preflight CORS
                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                            // Endpoints Públicos (no requieren autenticación)
                            .requestMatchers("/v1/auth/**", "/v1/auth/register").permitAll()
                            .requestMatchers(HttpMethod.POST, "/v1/payment/notifications").permitAll()
                            // Endpoints Protegidos (requieren rol ADMIN o DEV)
                            .requestMatchers("/v1/users/admin/**", "/v1/data/**",
                                                        "/v1/eventos/**", "/v1/payment/**")
                                                        .hasAnyRole("ADMIN", "DEV", "USER_PAID", "USER_TRIAL")
                            .requestMatchers("/v1/participantes/**", "/v1/qr/validate-qr")
                            .hasAnyRole("USER_PAID","USER_PAID_MONTHLY_COMMON", "USER_PAID_MONTHLY_PROFESSIONAL",
                                        "USER_PAID_MONTHLY_CORPORATE", "USER_TRIAL", "DEV")
                            // Cualquier otra petición requiere autenticación
                            .anyRequest().authenticated();
                })
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return daoAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

  @Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Opción A: Permitir solo tu localhost (Más seguro)
    configuration.setAllowedOrigins(List.of("http://localhost:3000")); 
    
    // Opción B: Si quieres permitir "todo", debes poner allowCredentials en false
    // configuration.setAllowedOriginPatterns(List.of("*"));
    // configuration.setAllowCredentials(false); 

    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
    configuration.setAllowCredentials(true); // Necesario si envías el JWT en las cookies o headers específicos
    configuration.setExposedHeaders(List.of("Authorization")); // Para que el front pueda leer el token

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
}
