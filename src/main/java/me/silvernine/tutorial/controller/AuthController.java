package me.silvernine.tutorial.controller;

import me.silvernine.tutorial.dto.LoginDto;
import me.silvernine.tutorial.dto.TokenDto;
import me.silvernine.tutorial.jwt.JwtFilter;
import me.silvernine.tutorial.jwt.TokenProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api")
public class AuthController {
    private final TokenProvider tokenProvider;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;

    /*
    생성자
     */
    public AuthController(TokenProvider tokenProvider, AuthenticationManagerBuilder authenticationManagerBuilder) {
        this.tokenProvider = tokenProvider;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
    }

    /*
    사용자 인증을 하고 JWT 토큰Dto를 담은 ResponseEntity<TokenDto> 리턴
     */
    @PostMapping("/authenticate")
    public ResponseEntity<TokenDto> authorize(@Valid @RequestBody LoginDto loginDto) {

        //일단 사용자 username, password를 기반으로 토큰을 생성
        /*
        public UsernamePasswordAuthenticationToken(Object principal, Object credentials) {
		    super(null);
		    this.principal = principal;
		    this.credentials = credentials;
		    setAuthenticated(false);
	    }
         */
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

        // AuthenticationManagerBuilder는 스프링 시큐리티에서 인증 관련 설정을 구성함.
        // authenticationManagerBuilder.getObject()를 통해서 AuthenticationManager 객체를 가져오고
        // authenticate()를 이용해 토큰을 인증한다.
        // AuthenticationException 예외 처리를 해줘야 함.
        //  예를 들어, 인증 실패 시 로그인 실패 메시지를 사용자에게 표시하거나 인증 실패 이유를 기록하는 등
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        // 스프링 시큐리티에 인증 정보 설정
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // jwt 토큰 생성
        String jwt = tokenProvider.createToken(authentication, loginDto.getUsername());

        // http 응답 헤더 설정
        HttpHeaders httpHeaders = new HttpHeaders();

        // JwtFilter.AUTHORIZATION_HEADER는 일반적으로 "Authorization" 문자열로 정의되고,
        // 그 헤더에 Bearer 와 jwt 문자열을 결합하여 저장한다.
        httpHeaders.add(JwtFilter.AUTHORIZATION_HEADER, "Bearer " + jwt);

        // ResponseEntity는 HttpEntity 의 자식 클래스로, HttpEntity 클래스에는 http 응답 메세지에 사용되는 헤더와 바디가 있다.
        // 그리고 이를 상속받은 ResponseEntity에는 상태 필드가 추가되어 있다.
        /*
        public ResponseEntity(@Nullable T body, @Nullable MultiValueMap<String, String> headers, int rawStatus) {
		    this(body, headers, (Object) rawStatus);
	    }
         */
        // 바디에 tokenDto, 헤더에는 헤더, 그리고 상태 OK(200, Series.SUCCESSFUL, "OK") 를 넣는다.
        // 정리하면, http 헤더에는 jwt토큰을 넣고, 바디에는 jwt토큰을 넣은 dto를 보내서 클라이언트에서 이 dto를 활용할 수 있게 한다.
        return new ResponseEntity<>(new TokenDto(jwt), httpHeaders, HttpStatus.OK);

        /*
        클라이언트는 HTTP 헤더에 포함된 정보를 사용할 수 있습니다. 그렇다면 왜 JWT 정보를 HTTP 응답 메시지의 본문에 넣는 것일까요?
        일반적으로 JWT 토큰은 인증을 위한 정보로 사용됩니다. 클라이언트는 JWT 토큰을 서버에 제출하여 인증을 요청하고,
        서버는 해당 토큰을 확인하여 클라이언트를 인증합니다. 이 때, JWT 토큰은 주로 HTTP 헤더의 "Authorization" 헤더에 포함하여 전송됩니다.

        그렇다면 JWT 정보를 HTTP 응답 메시지의 본문에 포함시키는 이유는 다음과 같습니다:

        인증 완료 메시지: JWT 토큰은 클라이언트의 인증을 나타내는 중요한 정보입니다. 클라이언트가 로그인 또는 인증 요청을 보낸 후,
        서버에서는 인증에 성공한 경우에 대한 응답을 전달해야 합니다.
        이때 응답 본문에 JWT 토큰을 포함시키면, 클라이언트는 토큰을 쉽게 추출하여 저장하고, 이후의 요청에 사용할 수 있습니다.

        추가 정보 포함: JWT 토큰은 단순히 인증에 사용되는 정보일 뿐만 아니라, 클라이언트에 대한 추가 정보를 포함시킬 수도 있습니다.
        예를 들어, 사용자 정보, 권한, 권한 만료일 등의 추가적인 사용자 관련 정보를 JWT 토큰과 함께 전달할 수 있습니다.
        이러한 정보를 응답 본문에 포함시키면, 클라이언트는 토큰과 함께 필요한 추가 정보를 한꺼번에 받을 수 있습니다.

        따라서, JWT 토큰은 주로 HTTP 헤더의 "Authorization" 헤더에 포함하여 전송되지만,
        JWT 정보를 HTTP 응답 메시지의 본문에 넣는 이유는 인증 완료 메시지와 추가 정보의 전달을 용이하게 하기 위함입니다.
        클라이언트는 본문에서 JWT 토큰을 추출하여 인증에 사용하고, 필요한 경우 추가 정보를 활용할 수 있습니다.
         */
    }
}
