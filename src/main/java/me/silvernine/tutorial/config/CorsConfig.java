package me.silvernine.tutorial.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
   /*
   Cross-Origin Resource Sharing(CORS)
   브라우저는 보안상의 이유로 다른 도메인에 있는 자원에 접근하는 cross-origin HTTP 요청을 제한한다. SOP(Same Origin Policy)
   이를 위해서는 서버의 동의가 필요한데, cross-origin 요청을 동의하는  Cross-Origin Resource Sharing 설정을 해야 한다.
   커스텀 필터인 corsFilter를 만들어 추가하면 이를 해결할 수 있다.
   */
   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();      //cors 관련 설정을 정의하고 구성

      config.setAllowCredentials(true);         //자격 증명 허용 여부 설정. Authorization을 이용해 인증 서비스를 할 때 true로 세팅
      config.addAllowedOriginPattern("*");      //모든 ip에 대해 응답을 허용
      config.addAllowedHeader("*");             //모든 header에 대해 응답을 허용
      config.addAllowedMethod("*");             //모든 매서드(get, post, put, delete..)에 대해 응답을 허용

      // registerCorsConfiguration은 지정된 경로에 대해 CorsConfiguration 적용
      // /api로 시작하는 모든 경로에 대해 cors 설정을 적용한다.
      source.registerCorsConfiguration("/api/**", config);

      return new CorsFilter(source);
   }
}
