package com.kazale.api.security.repositories;


import org.springframework.data.jpa.repository.JpaRepository;

import com.kazale.api.security.entities.Usuario;


@org.springframework.transaction.annotation.Transactional(readOnly = true)
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
	Usuario findByEmail(String email);
}
