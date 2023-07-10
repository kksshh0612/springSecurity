package me.silvernine.tutorial.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.silvernine.tutorial.jwt.TokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.stereotype.Service;


@Service
public class CustomRememberMeServices implements RememberMeServices {

    private static final String rememberMeCookieName = "remember-me";            //RememberMe 쿠키의 이름 (브라우저에 저장)
    private static final int tokenValidity = 86400;            //RememberMe 토큰의 유효 기간 (초 단위, 예: 24시간)

    /*
    RememberMe 토큰을 확인하고 유효한 경우에 Authebtication 객체를 생성하여 반환합니다.
     */
    @Override
    public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {

        String rememberMeToken = extractRememberMeToken(request);       //요청의 쿠키에서 RememberMe 토큰을 추출하여 반환
        if (rememberMeToken != null) {
            // RememberMe 토큰을 사용하여 사용자 인증 정보를 생성합니다.
            // 예: TokenProvider를 사용하여 토큰을 검증하고 사용자 정보를 추출합니다.
            // Authentication 객체를 생성하고 SecurityContext에 설정한 후 반환합니다.
        }
        return null; // 유효한 RememberMe 토큰이 없을 경우 null을 반환합니다.
    }

    @Override
    public void loginFail(HttpServletRequest request, HttpServletResponse response) {

        //로그아웃시 토큰 없어지게 구현하기 로그인 실패하면 그냥 실패한거.. 토큰 발행할 일이 없음.

        // 로그인 실패 시에 호출되는 메서드입니다.
        // 필요한 경우, 로그인 실패와 관련된 작업을 수행할 수 있습니다.
//        if(extractRememberMeToken(request) != null){        // 토큰이 있으면
//
//        }
    }

    @Override
    public void loginSuccess(HttpServletRequest request, HttpServletResponse response, Authentication successfulAuthentication) {
        // 로그인 성공 시에 호출되는 메서드입니다.
        // RememberMe 토큰을 생성하고, 응답의 쿠키에 토큰을 설정합니다.
        String rememberMeToken = generateRememberMeToken(successfulAuthentication.getPrincipal());
        setRememberMeCookie(response, rememberMeToken);
    }

    /*
    remember-me 토큰이 존재하는지 확인 후 반환
     */
    private String extractRememberMeToken(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();;

        if(cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(rememberMeCookieName)) {      //rememberMe 쿠키이면
                    return cookie.getValue();
                }
            }
        }
        return null;        //추출된 RememberMe 토큰이 없을 경우 null을 반환
    }

    /*
    remember-me 토큰 생성
     */
    private String generateRememberMeToken(Object principal) {
        TokenProvider tokenProvider = new TokenProvider();

        return tokenProvider.createRememberMeToken(principal);
    }

    /*
    http-response에 remember-me 토큰 설정
     */
    private void setRememberMeCookie(HttpServletResponse response, String rememberMeToken) {

        Cookie rememberMeCookie = new Cookie(rememberMeCookieName, rememberMeToken);
        rememberMeCookie.setPath("/");          //RememberMe 쿠키의 유효 범위를 전체 애플리케이션으로 설정
        rememberMeCookie.setSecure(true);       //HTTPS 프로토콜에서만 쿠키 전송을 허용하도록 설정
        rememberMeCookie.setHttpOnly(true);     //JavaScript에서 쿠키에 접근하지 못하도록 설정
        response.addCookie(rememberMeCookie);
    }
}