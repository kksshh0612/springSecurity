package me.silvernine.tutorial.service;

import java.util.Collections;
import java.util.Optional;
import me.silvernine.tutorial.dto.UserDto;
import me.silvernine.tutorial.entity.Authority;
import me.silvernine.tutorial.entity.User;
import me.silvernine.tutorial.exception.DuplicateMemberException;
import me.silvernine.tutorial.exception.NotFoundMemberException;
import me.silvernine.tutorial.repository.UserRepository;
import me.silvernine.tutorial.util.SecurityUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    /*
    생성자
     */
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /*
    회원가입
     */
    @Transactional
    public UserDto signup(UserDto userDto) {
        //username으로 유저를 찾고 존재하면 예외 처리
        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        //ROLE_USER 권한 설정
        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        // User 엔티티 객체 만들기
        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))    //비밀번호를 인코딩해서 저장
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))      //Collections.singleton은 set의 구현체를 반환. 또한, 읽기 전용으로 다른 작업 불가능.
                .activated(true)
                .build();

        return UserDto.from(userRepository.save(user));     //UserDto 반환
    }

    /*
    User를 찾고, 없으면 null을 반환하고 있으면 UserDto 반환
     */
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {

        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    /*
    현재 시큐리티 컨텍스트에 저장되어있는 유저 객체를 찾아 UserDto를 반환
     */
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(
                // SecurityUtil.getCurrentUsername() : 현재 스프링 시큐리티 컨텍스트에 인증된 사용자의 이름을 Optional 객체로 가져옴
                // 두번째 줄에서는 사용자 이름으로 User 객체를 찾아옴
                // 찾지 못하면 NotFoundMemberException 예외를 터뜨림
                SecurityUtil.getCurrentUsername()
                        .flatMap(userRepository::findOneWithAuthoritiesByUsername)
                        .orElseThrow(() -> new NotFoundMemberException("Member not found"))
        );
    }
}
