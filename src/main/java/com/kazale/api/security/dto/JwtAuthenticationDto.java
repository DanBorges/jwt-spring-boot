package com.kazale.api.security.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotEmpty;

public class JwtAuthenticationDto {
	

	@NotEmpty(message = "Email não pode ser vazio")
	@Email
	private String email;
	
	@NotEmpty(message = "Senha não pode ser vazio")
	private String senha;
	
	public JwtAuthenticationDto() {
		
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getSenha() {
		return senha;
	}

	public void setSenha(String senha) {
		this.senha = senha;
	}
	
	

}
