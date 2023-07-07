package me.silvernine.tutorial.jwt;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private TokenProvider tokenProvider;

    /*
    생성자
     */
    public JwtSecurityConfig(TokenProvider tokenProvider) {
        this.tokenProvider = tokenProvider;
    }

    /*
    UsernamePasswordAuthenticationFilter 앞에 커스텀 필터 등록
    UsernamePasswordAuthenticationFilter는 request에서 username, password를 가져와서 UsernamePasswordAuthenticationToken 를 생성한 후
    AuthenticationManager를 구현한 객체에 인증을 위임한다.
     */
    @Override
    public void configure(HttpSecurity http) {
        // UsernamePasswordAuthenticationFilter 앞에 JwtFilter 추가
        http.addFilterBefore(new JwtFilter(tokenProvider), UsernamePasswordAuthenticationFilter.class);
    }
}
