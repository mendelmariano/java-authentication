package com.novidades.gestaodeprojetos.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.novidades.gestaodeprojetos.config.SecurityConfig;

@Configuration
@EnableWebSecurity // Aqui informo que é uma classe de segurança do WebSecurity
@Import(SecurityConfig.class)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JWTAuthenticaiontFilter jwtAuthenticaiontFilter;

    //Método que devolve a instância do objeto que sabe devolover o nosso padrão de codificação
    // Isso não tem nada a ver com jwt

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Método padrão para configurar nosso custom com nosso método de codificar senha
    @Override
    public void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder
            .userDetailsService(customUserDetailsService)
            .passwordEncoder(passwordEncoder());
    } 



    // Método padrão: Esse método é obrigatório para conseguirmos trtabalhar com a autenticação no login
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    // Método que tem a configuração global de acessos e permissões por rotas
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // Parte padrão da configuração, por enquanto ignorar
        http
            .cors().and().csrf().disable()
            .exceptionHandling()
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()


            /*
             * Daqui pra baixo serão as validações
             */

             .antMatchers(HttpMethod.POST, "/api/usuarios", "/api/usuarios/login")
             .permitAll() // Informa que todos podem acessar, não precisa de autenticação.

             .anyRequest()
             .authenticated(); // Digo que as demais rotas devem ser autenticadas

        // Aqui eu informo que antes de qualquer requisicao http, o sistema deve usar o nosso filtro jwtAuthenticaiontFilter
        http.addFilterBefore(jwtAuthenticaiontFilter, UsernamePasswordAuthenticationFilter.class);
             
    }
}
