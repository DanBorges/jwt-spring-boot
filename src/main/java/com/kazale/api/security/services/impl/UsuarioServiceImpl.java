package com.kazale.api.security.services.impl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.kazale.api.security.entities.Usuario;
import com.kazale.api.security.repositories.UsuarioRepository;
import com.kazale.api.security.services.UsuarioService;

@Service
public class UsuarioServiceImpl implements UsuarioService {
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
	public Optional<Usuario> buscarPorEmail(String email) {
		return java.util.Optional.ofNullable(this.usuarioRepository.findByEmail(email));
	}
}
