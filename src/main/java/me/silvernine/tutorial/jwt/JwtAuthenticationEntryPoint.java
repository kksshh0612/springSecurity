package me.silvernine.tutorial.jwt;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {
   // AuthenticationEntryPoint : 인증되지 않은 유저가 요청하면 동작. ex) 로그인하지 않은 사용자가 접속 시도
   @Override
   public void commence(HttpServletRequest request,
                        HttpServletResponse response,
                        AuthenticationException authException) throws IOException {
      // 인증을 하지 않고 접근하려 할 때
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);    //SC_UNAUTHORIZED : 401
   }
}
