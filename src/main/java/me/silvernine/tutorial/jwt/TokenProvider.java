package me.silvernine.tutorial.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

   private final Logger logger = LoggerFactory.getLogger(TokenProvider.class);
   private static final String AUTHORITIES_KEY = "auth";    //권한
   private final String secret;
   private final long tokenValidityInMilliseconds;
   private Key key;

   /*
   생성자
    */
   public TokenProvider(
      @Value("#{environment['jwt.secret']}") String secret,
      @Value("#{environment['jwt.token-validity-in-seconds']}") long tokenValidityInSeconds) {
      this.secret = secret;
      this.tokenValidityInMilliseconds = tokenValidityInSeconds * 1000;
   }

   /*
   빈이 생성되고 의존관계 주입까지 완료된 후, Key 변수에 값 할당
    */
   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(secret);     //생성자 주입으로 받은 secret 값을 Base64에 디코딩하여 key 변수에 할당
      this.key = Keys.hmacShaKeyFor(keyBytes);              //hmac 알고리즘을 이용하여 Key 인스턴스 생성
   }

   /*
    Authentication 객체의 권한 정보를 이용하여 access 토큰(문자열)을 생성
    참고로, 스프링 시큐리티에서는 cridential 기반 인증을 진행
     */
   public String createToken(Authentication authentication, String username) {
      String authorities = authentication.getAuthorities().stream()     //권한 정보
         .map(GrantedAuthority::getAuthority)
         .collect(Collectors.joining(","));

      long now = (new Date()).getTime();     //현재 시간
      Date validity = new Date(now + this.tokenValidityInMilliseconds);    //현재시간 + 토큰 유효 시간 == 만료날짜

      System.out.println("여기여기여기");

      // jws == header(json) + payload(json) + signature( sign(header+payload) )
      // claim은 jwt 안에 넣고싶은 정보들. Standard Claims은 setter를 이용해 기본적인 정보들을 넣을 수 있게 해준다.
      // 기본으로 등록되 claim 말고 새로운 것을 넣고싶으면 customclaim을 이용한다. .claim()
      // 등록된 클레임, 공개 클레임, 비공개 클레임이 있다.
      // 공개 클레임을 사용할 때는 uri를 사용하여 고유하게 만든다.
      return Jwts.builder()                     //JwtBuilder 객체를 생성
         .setSubject(authentication.getName())        // payload "sub": "name"
         .claim(AUTHORITIES_KEY, authorities)         // payload "auth": "ROLE_USER"
         .setExpiration(validity)                     // payload "exp": 1516239022 (예시)
         .signWith(key, SignatureAlgorithm.HS512)     // header "alg": "HS512"
         .compact();       //압축하고 서명하여 jws 생성
   }

   /*
   jwt 토큰을 받아 권한 정보들을 이용해 authentication 객체를 생성 후 리턴
    */
   public Authentication getAuthentication(String token) {

      System.out.println("access 토큰 : " + token);       //access 토큰

      Claims claims = Jwts.parserBuilder()                  //JwtParserBuilder 객체 생성
              .setSigningKey(key)             //시크릿 키(서버에서 가지고 있는 키) 서명 검증
              .build()                        //JwtParser 생성
              .parseClaimsJws(token)
              .getBody();

      // claims는 claim에 뭐가 들어있을까: {sub=admin, username=admin, exp=1688709600} 이렇게 출력됨.
      System.out.println("claim에 뭐가 들어있을까: " + claims);

      // claim에서 권한 정보 가져오기
      Collection<? extends GrantedAuthority> authorities =
         Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))     //claims.get(AUTHORITIES_KEY).toString().split(",")
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

      System.out.println(authorities);

      User principal = new User(claims.getSubject(), "", authorities);

      // Authentication 인터페이스의 구현 클래스 
      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   /*
   유효한 토큰인지 확인
    */
   public boolean validateToken(String token) {
      try {
         Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         logger.info("잘못된 JWT 서명입니다.");
      } catch (ExpiredJwtException e) {
         logger.info("만료된 JWT 토큰입니다.");
      } catch (UnsupportedJwtException e) {
         logger.info("지원되지 않는 JWT 토큰입니다.");
      } catch (IllegalArgumentException e) {
         logger.info("JWT 토큰이 잘못되었습니다.");
      }
      return false;
   }
}
