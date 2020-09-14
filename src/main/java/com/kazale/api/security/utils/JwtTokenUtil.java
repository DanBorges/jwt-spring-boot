package com.kazale.api.security.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


@Component
public class JwtTokenUtil {
	static final String CLAIM_KEY_USERNAME = "sub";
	static final String CLAIM_KEY_ROLE = "role";
	static final String CLAIM_KEY_CREATED = "created";
	
	@Value("${jwt.secret}")
	private String secret;
	
	@Value("${jwt.expiration}")
	private Long expiration;
	
//	Obtem email
	public String getUsernameFromToken(String token) {
		String username;
		try {
			Claims claims = getClaimsFromToken(token);
			username = claims.getSubject();
		} catch (Exception e) {
			username = null;
		}
		return username;
	}
	
//	retorna data de expiração do token
	public Date getExpirationDateFromToken (String token) {
		Date expiration;
		try {
			Claims claims = getClaimsFromToken(token);
			expiration = claims.getExpiration();
		} catch (Exception e) {
			expiration = null;
		}
		return expiration;
	}
	
	
//	Cria novo token (refresh)
	
	public String refreshToken(String token) {
		String refreshedToken;
		try {
			Claims claims = getClaimsFromToken(token);
			claims.put(CLAIM_KEY_CREATED, new Date());
			refreshedToken = gerarToken(claims);
		} catch (Exception e) {
			refreshedToken = null;
		}
		
		return refreshedToken;
	}
	
//	Verifica se token é valido
	
	public boolean tokenValido(String token) {
		return !tokenExpirado(token);
	}
	
//	Retorna novo token JWT com base nos dados do Usuário
	
	public String obterToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
		userDetails.getAuthorities().forEach(authoritary -> claims.put(CLAIM_KEY_ROLE, authoritary.getAuthority()));
		claims.put(CLAIM_KEY_CREATED, new Date());
		return gerarToken(claims);
	}
	
//	Realiza o parse do token JWT para extrair informações contidas no corpo
	
	private Claims getClaimsFromToken(String token) {
		Claims claims;
		try {
			claims = Jwts.parser().setSigningKey(secret).parseClaimsJwt(token).getBody();
		} catch (Exception e) {
			claims = null;
		}
		return claims;
	}
	 
//	Retorna data de expiração com base na data atual
	
	private Date gerarDataExpiracao() {
		return new Date(System.currentTimeMillis() + expiration *1000);
	}
	
	
//	Verfica se token JWT está expirado
	
	
	private boolean tokenExpirado(String token) {
		Date dataExpiracao = this.getExpirationDateFromToken(token);
		if(dataExpiracao == null) {
			return false;
		}
		return dataExpiracao.before(new Date());
	}
	
	
//	Gera um novo token JWT contando dados claims forneceidos
	
	private String gerarToken(Map<String, Object> claims) {
		return Jwts.builder().setClaims(claims)
								.setExpiration(gerarDataExpiracao())
								.signWith(SignatureAlgorithm.HS512, secret).compact();
	}


}
