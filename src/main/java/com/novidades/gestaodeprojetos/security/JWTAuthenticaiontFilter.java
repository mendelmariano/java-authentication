package com.novidades.gestaodeprojetos.security;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JWTAuthenticaiontFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    // Método principal onde toda a requisição bate antes de chegar no nosso endpoint.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


      
                // Pego o token de dentro da requisição.
                String token = obterToken(request);

                // Pego o id do usuário que está dentro da requisição
                Optional<Long> id = jwtService.obterIdDousuario(token);

                if(id.isPresent()) {
                

                // Pego o usuário dono do token pelo seu id.
                UserDetails usuario = customUserDetailsService.obterUsuarioPorId(id.get());

                // Neste ponto verificamos se o usuário está autenticado ou não. Poderíamos também validar as permissões
                UsernamePasswordAuthenticationToken autenticacao = 
                new UsernamePasswordAuthenticationToken(usuario, null, Collections.emptyList());

                // Mudando a autenticação para a própria requisição
                autenticacao.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Repasso a autenticação para o contexto do security. O Spring toma conta de tudo para mim.
                SecurityContextHolder.getContext().setAuthentication(autenticacao);
                }

                // Método padrão para filtrar as regras do usuário
                filterChain.doFilter(request, response);
        
    }

    private String obterToken(HttpServletRequest request) {

        String token = request.getHeader("Authorization");

        //Verifica se veio alguma coisa sem ser espaços em branco dentro do token
        if(!StringUtils.hasText(token)) {
            return null; 
        }

        return token.substring(7);

        // Bearer as12312aklsalsdnalksdfn234234234.234234asddsa

    }
    
}
