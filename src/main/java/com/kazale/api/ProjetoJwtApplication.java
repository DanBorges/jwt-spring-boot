package com.kazale.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import com.kazale.api.security.entities.Usuario;
import com.kazale.api.security.enums.PerfilEnum;
import com.kazale.api.security.repositories.UsuarioRepository;
import com.kazale.api.utils.SenhaUtils;

@SpringBootApplication
public class ProjetoJwtApplication {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	
	
	public static void main(String[] args) {
		SpringApplication.run(ProjetoJwtApplication.class, args);
	}
	
	@Bean
	public CommandLineRunner commandLineRunner() {
		return args -> {
			Usuario usuario = new Usuario();
			usuario.setEmail("daniel.lemes.borges@gmail.com");
			usuario.setSenha(SenhaUtils.gerarBCrypt("123456"));
			usuario.setPerfil(PerfilEnum.ROLE_USUARIO);
			this.usuarioRepository.save(usuario);
			
			Usuario admin = new Usuario();
			admin.setEmail("lemebor91@yahoo.com");
			admin.setSenha(SenhaUtils.gerarBCrypt("12345678"));
			admin.setPerfil(PerfilEnum.ROLE_ADMIN);
			this.usuarioRepository.save(admin);
			
			System.out.println("###################################" + usuarioRepository.findAll());
			
		};
	}

}
