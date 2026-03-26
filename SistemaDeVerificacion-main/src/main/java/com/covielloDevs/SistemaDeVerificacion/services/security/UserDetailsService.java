package com.covielloDevs.SistemaDeVerificacion.services.security;

import com.covielloDevs.SistemaDeVerificacion.repositories.UsuarioRepository;
import com.covielloDevs.SistemaDeVerificacion.utils.exceptions.usuario.UsuarioNotFoundException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public UserDetailsService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

  @Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

    Usuario usuario = usuarioRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));

    System.out.println("ROL DESDE SECURITY: " + usuario.getRol());

    return new User(
            usuario.getUsername(),
            usuario.getPassword(),
            List.of(new SimpleGrantedAuthority("ROLE_" + usuario.getRol().name()))
    );
}
