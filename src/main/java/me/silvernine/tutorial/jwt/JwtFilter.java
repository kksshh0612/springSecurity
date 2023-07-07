package me.silvernine.tutorial.jwt;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;

public class JwtFilter extends GenericFilterBean {

   private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
   public static final String AUTHORIZATION_HEADER = "Authorization";
   private TokenProvider tokenProvider;

   /*
   생성자
    */
   public JwtFilter(TokenProvider tokenProvider) {
      this.tokenProvider = tokenProvider;
   }

   @Override
   public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
      HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
      String jwt = resolveToken(httpServletRequest);              //access 토큰 문자열
      String requestURI = httpServletRequest.getRequestURI();

      System.out.println("requestURI" + requestURI);

      //jwt 문자열이 null이 아니고 유효한 토큰이면 스프링 시큐리티 컨텍스트에 Authentication 객체 저장
      if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
         Authentication authentication = tokenProvider.getAuthentication(jwt);      //UsernamePasswordAuthenticationToken 객체 저장
         SecurityContextHolder.getContext().setAuthentication(authentication);
         logger.debug("Security Context에 '{}' 인증 정보를 저장했습니다, uri: {}", authentication.getName(), requestURI);
      } else {
         logger.debug("유효한 JWT 토큰이 없습니다, uri: {}", requestURI);
      }

      filterChain.doFilter(servletRequest, servletResponse);
   }

   /*
   HttpServletRequest의 헤더에서 JWT 토큰 받아서 access 토큰 반환
    */
   private String resolveToken(HttpServletRequest request) {
      //bearer는 인증 타입중 하나로, jwt, oauth에 대한 토큰을 사용하는 인증을 뜻한다.
      String bearerToken = request.getHeader(AUTHORIZATION_HEADER);

      System.out.println(bearerToken);

      //StringUtils.hasText() : 공백이나 null이면 false
      //bearer 토큰은 'Bearer JWT 문자열' 이렇게 구성됨
      if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
         return bearerToken.substring(7);       //JWT에서 "Bearer " 이부분 슬라이싱
      }

      return null;
   }
}
