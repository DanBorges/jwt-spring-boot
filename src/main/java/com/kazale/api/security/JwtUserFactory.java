package com.kazale.api.security;

import java.util.ArrayList;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.kazale.api.security.entities.Usuario;
import com.kazale.api.security.enums.PerfilEnum;

import java.util.List;

public class JwtUserFactory {
	
	private JwtUserFactory() {
		
	}
	
//	Converte e gera um JWT com base nos dados do funcionário
	public static JwtUser create(Usuario usuario) {
		return new JwtUser(usuario.getId(), 
							usuario.getEmail(), 
							usuario.getSenha(), 
							mapToGrantedAuthorities(usuario.getPerfil()));
							
		
	}
	
//	converte o perfil do usuario no padrao usuado no Spring security
	
	private static List<GrantedAuthority> mapToGrantedAuthorities(PerfilEnum perfilEnum) {
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(perfilEnum.toString()));
		return authorities;
	}

}
