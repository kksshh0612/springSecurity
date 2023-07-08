package me.silvernine.tutorial.config;

import me.silvernine.tutorial.jwt.JwtSecurityConfig;
import me.silvernine.tutorial.jwt.JwtAccessDeniedHandler;
import me.silvernine.tutorial.jwt.JwtAuthenticationEntryPoint;
import me.silvernine.tutorial.jwt.TokenProvider;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity      //기본적인 웹 보안 활성화
@EnableMethodSecurity
@Configuration
public class SecurityConfig {                       //스프링 시큐리티 관련 설정

    private final TokenProvider tokenProvider;
    private final CorsFilter corsFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final RememberMeServices rememberMeServices;

    /*
    생성자
     */
    public SecurityConfig(
        TokenProvider tokenProvider,
        CorsFilter corsFilter,
        JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint,
        JwtAccessDeniedHandler jwtAccessDeniedHandler,
        RememberMeServices rememberMeServices
    ) {
        this.tokenProvider = tokenProvider;
        this.corsFilter = corsFilter;
        this.jwtAuthenticationEntryPoint = jwtAuthenticationEntryPoint;
        this.jwtAccessDeniedHandler = jwtAccessDeniedHandler;
        this.rememberMeServices = rememberMeServices;
    }

    /*
    BCryptPasswordEncoder는 스프링 시큐리티에서 제공하는 클래스중 하나로, PasswordEncoder 인터페이스의 구현체이다.
    encode(CharSequence rawPassword); : BCrypt 해싱 함수를 사용해 비밀번호를 해싱해주는 매서드 **CharSequence의 구현체는 String, StringBuffer
    matches(CharSequence rawPassword, String encodedPassword) : 인코딩하지 않은 패스워드 문자열과 인코딩된 패스워드 문자열이 같은지 판별해주는 매서드
    upgradeEncoding(String encodedPassword) : 인코딩이 필요한지 안필요한지 판별. true / false
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    스프링 시큐리티 구성을 정의하는 필터체인 구성
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            //API 통신을 하는 애플리케이션의 경우 csrf 공격을 받을 가능성이 없기 때문에 @EnableWebSecurity의 csrf 보호 기능을 해제
            .csrf(csrf -> csrf.disable())

            //UsernamePasswordAuthenticationFilter 앞에 corsFilter 추가
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)

            //각 예외 인터페이스를 커스텀한 두 예외 등록. 401, 403 에러
            .exceptionHandling(exceptionHandling -> exceptionHandling
                .accessDeniedHandler(jwtAccessDeniedHandler)
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
            )

            //http 요청에 대한 접근 권한을 설정한다.
            //로그인, 회원가입 api는 토큰이 없는 상태로 요청이 들어오기 때문에 permitAll()로 열어줌
            .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                .requestMatchers("/api/hello", "/api/authenticate", "/api/signup").permitAll()
                .requestMatchers(PathRequest.toH2Console()).permitAll()     //H2 콘솔에 대한 접근 허용
                .anyRequest().authenticated()       //나머지 요청은 모두 권한 필요함.
            )

            // 세션을 사용하지 않기 때문에 STATELESS로 설정
            .sessionManagement(sessionManagement ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            //브라우저 자동 로그인
            .rememberMe(rememberMe -> rememberMe
                    .key("uniqueKey")                       // 토큰을 암호화하는 데 사용될 키
                    .rememberMeServices(rememberMeServices) // RememberMeServices 인터페이스를 구현한 구체적인 서비스
                    .tokenValiditySeconds(86400)            // 토큰의 유효 기간과 같게 설정
            )

            // 헤더 관련 설정
            .headers(headers ->
                headers.frameOptions(options ->
                    options.sameOrigin()            //동일 출처에서만 h2 데이터베이스 접근.
                )
            )

            // JwtSecurityConfig 클래스를 이용하여 JWT 관련 설정 적용용
           .apply(new JwtSecurityConfig(tokenProvider));

        return http.build();
    }
}