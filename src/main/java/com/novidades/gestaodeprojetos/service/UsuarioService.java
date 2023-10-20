package com.novidades.gestaodeprojetos.service;


import java.util.Collections;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.novidades.gestaodeprojetos.model.Usuario;
import com.novidades.gestaodeprojetos.repository.UsuarioRepository;
import com.novidades.gestaodeprojetos.security.JWTService;
import com.novidades.gestaodeprojetos.view.model.usuario.LoginResponse;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class UsuarioService {

    private static final String headerPrefix = "Bearer ";

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder; 
    

    @Autowired
    private UsuarioRepository repositorioUsuario;

   

    @Autowired
    private JWTService jwtService;
 
    @Autowired
    private AuthenticationManager authenticationManager;



    public List<Usuario> obterTodos() {
        return repositorioUsuario.findAll();
    }

    public Optional<Usuario> obterPorId(Long id) {
        return repositorioUsuario.findById(id);
    }

    public Optional<Usuario> obterPorEmail(String email) {
        return repositorioUsuario.findByEmail(email);
    }

    public Usuario adicionar(Usuario usuario) {
        usuario.setId(null);

        if(obterPorEmail(usuario.getEmail()).isPresent()) {
            //Aqui poderia lançar ma exception informando que o usuário já existe
            throw new InputMismatchException("Já existe um usuário cadastrado com este email! "+ usuario.getEmail());
        }

        // Aqui eu estou codificando a senha para não ficar pública, gerando um hash
        /* String senha = passwordEncoder.encode(usuario.getSenha());

        usuario.setSenha(senha); */
        String senhaCriptografada = bCryptPasswordEncoder.encode(usuario.getSenha());
        usuario.setSenha(senhaCriptografada);
        
        return repositorioUsuario.save(usuario);
    }

    public LoginResponse logar( String email, String senha) {
        
// Aqui que a autenticação acontece'
        Authentication autenticacao = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(email, senha, Collections.emptyList()));

        SecurityContextHolder.getContext().setAuthentication(autenticacao);

        String token = headerPrefix + jwtService.gerarToken(autenticacao);

        Usuario usuario = repositorioUsuario.findByEmail(email).get();

        return new LoginResponse(token, usuario);

    }
}
