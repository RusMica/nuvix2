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
                        // 1. Preflight CORS
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // 2. Endpoints Públicos
                        //.requestMatchers("/v1/auth/**", "/v1/auth/register").permitAll()
                       // .requestMatchers("/v1/users/email").authenticated()
                        // Busca esta línea y asegúrate de que esté ARRIBA de todas las demás reglas
.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
        // Ponemos la ruta que falla como TOTALMENTE PÚBLICA arriba de todo
        .requestMatchers("/v1/users/email").permitAll() 
        .requestMatchers("/v1/auth/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/v1/payment/notifications").permitAll()

                        // 3. Endpoints Protegidos (Usamos hasAnyAuthority con el nombre exacto)
                        .requestMatchers("/v1/users/admin/**", "/v1/data/**", 
                                         "/v1/eventos/**", "/v1/payment/**")
                                .hasAnyAuthority("ADMIN", "ROLE_ADMIN", "DEV", "USER_PAID", "ROLE_DEV", "ROLE_USER_PAID", "USER_TRIAL", "ROLE_USER_TRIAL")

                        // 4. Endpoints específicos de suscripción
                        .requestMatchers("/v1/participantes/**", "/v1/qr/validate-qr")
                                .hasAnyAuthority("ROLE_USER_PAID", "ROLE_USER_PAID_MONTHLY_COMMON", 
                                                 "ROLE_USER_PAID_MONTHLY_PROFESSIONAL", 
                                                 "ROLE_USER_PAID_MONTHLY_CORPORATE", "ROLE_USER_TRIAL", "ROLE_DEV")

                        // 5. El resto requiere autenticación
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
    
    // Agregamos tanto el local como el de Render
    configuration.setAllowedOrigins(List.of(
        "http://https://nuvix2.onrender.com",           // Tu PC
        "https://localhost:3000" // Tu sitio en Render
    )); 
    
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
    configuration.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
}
