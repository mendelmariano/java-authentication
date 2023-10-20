package com.novidades.gestaodeprojetos.security;

import java.util.Date;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.novidades.gestaodeprojetos.model.Usuario;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTService {
    
    // Chave secreta usada pelo JWT para codificar e decodificar o token
    /**Metodo para gerar o token JWT
     * @Param authentication
     * @return Token
     */
    private static final String chavePrivadaJWT = "secretKey";

    public String gerarToken(Authentication authentication) {
        // 1 dia em ms
        // Aqui pode variar de acordo com a sua regra de negócio
        int tempoExpiracao = 86400000;

        // Aqui estou criando uma data de expiração para o token com base no tempo de expiração
        Date dataExpiracao = new Date(new Date().getTime() + tempoExpiracao);

        // Aqui pegamos o usuário atual da autenticação
        Usuario usuario = (Usuario) authentication.getPrincipal();



        // Aqui ele pega todos os dados e retorna um token bonito do JWT
        return Jwts.builder()
            .setSubject(usuario.getId().toString())
            .setIssuedAt(new Date())
            .setExpiration(dataExpiracao)
            .signWith(SignatureAlgorithm.HS256, chavePrivadaJWT)
            .compact();
    }


    // Método para retornar o Id do usuário dono do token
    /**
     * 
     * @param token Token do usuáro
     * @return id do usuário
     */
    public Optional<Long> obterIdDousuario(String token) {

        try {
            // Retorna as permissões do token
            Claims claims = parse(token).getBody();

            // Retorna o id do usuário
            return Optional.ofNullable(Long.parseLong(claims.getSubject()));

        }catch(Exception e) {
            // Se não encontrar nada devolve um optional 
            return Optional.empty();
        }
    }

    // Método que sabe descobrir de dentro do token com base na chave privada, qual as permissões do usuário
    private Jws<Claims> parse(String token) {
        return Jwts.parser().setSigningKey(chavePrivadaJWT).parseClaimsJws(token);
    }
}
