package me.silvernine.tutorial.jwt;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
   // AccessDeniedHandler :서버에 요청을 할 때 권한을 체크 후 권한에 맞지 않으면 동작. ex) 관리자 페이지 접속 시도

   // 스프링 시큐리티에는 AccessDeniedHandler 와 AuthenticationEntryPoint 가 있다.
   // AccessDeniedHandler :서버에 요청을 할 때 권한을 체크 후 권한에 맞지 않으면 동작. ex) 관리자 페이지 접속 시도
   // AuthenticationEntryPoint : 인증되지 않은 유저가 요청하면 동작. ex) 로그인하지 않은 사용자가 접속 시도

   @Override
   public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException {
      // 권한이 충족되지 않았는데 접근할 때
      response.sendError(HttpServletResponse.SC_FORBIDDEN);    //SC_FORBIDDEN : 403
   }
}
