package com.kazale.api.security.services;

import java.util.Optional;

import com.kazale.api.security.entities.Usuario;


public interface UsuarioService {
	
	Optional<Usuario> buscarPorEmail(String email);

}
