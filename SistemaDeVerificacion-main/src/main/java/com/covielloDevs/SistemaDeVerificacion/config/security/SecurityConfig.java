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
    return http
            // 1. Desactivamos CSRF (necesario para APIs) y configuramos CORS
            .csrf(AbstractHttpConfigurer::disable)
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // 2. Política de sesión sin estado (Stateless)
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            
            // 3. Configuración de permisos de rutas
            .authorizeHttpRequests(auth -> {
                auth
                    // A. Permitir siempre las peticiones OPTIONS (Preflight de CORS)
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                    // B. Endpoints Públicos (No necesitan Token)
                    .requestMatchers("/v1/auth/**").permitAll()
                    .requestMatchers("/v1/users/email").permitAll() // La dejamos pública para testear
                    .requestMatchers(HttpMethod.POST, "/v1/payment/notifications").permitAll()

                    // C. Endpoints Protegidos por Roles (ADMIN, DEV, etc.)
                    .requestMatchers("/v1/users/admin/**", "/v1/data/**", "/v1/eventos/**", "/v1/payment/**")
                        .hasAnyAuthority("ADMIN", "ROLE_ADMIN", "DEV", "ROLE_DEV", "USER_PAID", "ROLE_USER_PAID", "USER_TRIAL", "ROLE_USER_TRIAL")

                    // D. Endpoints específicos de suscripción/QR
                    .requestMatchers("/v1/participantes/**", "/v1/qr/validate-qr")
                        .hasAnyAuthority("ROLE_USER_PAID", "ROLE_USER_PAID_MONTHLY_COMMON", 
                                         "ROLE_USER_PAID_MONTHLY_PROFESSIONAL", 
                                         "ROLE_USER_PAID_MONTHLY_CORPORATE", "ROLE_USER_TRIAL", "ROLE_DEV")

                    // E. Cualquier otra ruta requiere estar autenticado
                    .anyRequest().authenticated();
            })
            
            // 4. Proveedor de autenticación y Filtro JWT
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
    
    // 1. Orígenes permitidos (Local y Producción)
    configuration.setAllowedOrigins(List.of(
        "http://localhost:3000", 
        "https://nuvix2.onrender.com"
    ));
    
    // 2. Métodos permitidos
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    
    // 3. Headers permitidos
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "X-Requested-With"));
    
    // 4. Permitir credenciales
    configuration.setAllowCredentials(true);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    
    // 5. Registro y retorno
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
}
