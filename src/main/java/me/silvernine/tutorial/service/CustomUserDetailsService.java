package me.silvernine.tutorial.service;

import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.repository.UserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Component("userDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

   private final UserRepository userRepository;

   /*
   생성자
    */
   public CustomUserDetailsService(UserRepository userRepository) {
      this.userRepository = userRepository;
   }

   /*
   매개변수로 받은 사용자 이름으로 DB에서 사용자를 찾아 UserDetails 객체를 반환한다.
   UserDetails는 사용자 세부 정보를 나타내는 인터페이스인데 이름, 비밀번호, 권한, 활성화 여부, 계정 만료 여부, 계정 lock 여부 등을 나타내는
   매서드를 갖고있다.
    */
   @Override
   @Transactional
   public UserDetails loadUserByUsername(final String username) {
      return userRepository.findOneWithAuthoritiesByUsername(username)
         .map(user -> createUser(username, user))
         .orElseThrow(() -> new UsernameNotFoundException(username + " -> 데이터베이스에서 찾을 수 없습니다."));
   }

   /*
   사용자 이름과 User 객체(엔티티)를 이용하여 UserDetails의 구현 클래스인 User 객체를 생성한다.
   사용자 권한을 GrantedAuthority 리스트로 만들어 UserDetails의 구현 클래스인 User 객체를 반환한다.
    */
   private org.springframework.security.core.userdetails.User createUser(String username, User user) {
      if (!user.isActivated()) {    //현재 계정이 활성화 계정인지 판단
         throw new RuntimeException(username + " -> 활성화되어 있지 않습니다.");
      }

      //GrantedAuthority는 스프링 시큐리티 인터페이스로, getAuthority(); 매서드를 갖고 있다.
      //구현체로 SimpleGrantedAuthority가 있는데, 문자열 형태로 권한을 저장하고 반환한다.
      List<GrantedAuthority> grantedAuthorities = user.getAuthorities().stream()
              .map(authority -> new SimpleGrantedAuthority(authority.getAuthorityName()))
              .collect(Collectors.toList());

      return new org.springframework.security.core.userdetails.User(user.getUsername(),
              user.getPassword(),
              grantedAuthorities);
   }
}
