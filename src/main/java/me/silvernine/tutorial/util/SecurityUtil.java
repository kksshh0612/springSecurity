package me.silvernine.tutorial.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public class SecurityUtil {

   private static final Logger logger = LoggerFactory.getLogger(SecurityUtil.class);

   private SecurityUtil() {}

   public static Optional<String> getCurrentUsername() {
      //스프링 시큐리티 컨텍스트에 저장된 현재 사용자의 인증 정보 가져옴
      final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

      if (authentication == null) {
         logger.debug("Security Context에 인증 정보가 없습니다.");
         return Optional.empty();
      }

      String username = null;

      // 인증 객체의 principal은 사용자를 식별하는 정보를 의미하는데, UserDetails 인터페이스를 구현한 객체가 될 수 있고,
      // 사용자의 이름(아이디)가 될 수도 있다.
      // authentication.getPrincipal()의 반환값은 Object이다.
      if (authentication.getPrincipal() instanceof UserDetails) {    //인증 객체의 principal이 UserDetails 인터페이스를 구현한 객체일 경우
         UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
         username = springSecurityUser.getUsername();                //유저 이름 저장
      } else if (authentication.getPrincipal() instanceof String) {
         username = (String) authentication.getPrincipal();          //유저 이름 저장
      }

      return Optional.ofNullable(username);     //username이 null이면 비어있는 Optional 객체 반환
   }
}
