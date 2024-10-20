package tacos.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/*책의 실습에는 Spring Security 버전이  낮기 때문에 해당 클래스는 WebSecurityConfigurerAdapter 클래스를 상속받아 구현하였지만,
      현재 Spring Security 6.3.3 기준 해당 클래스는 지원 중단 되었고 SecurityFilterChain을 Bean으로 등록하여 사용함
      그에 맞게 설정들을 서칭하여 책의 설정들을 최신 버전에 맞게 변경하였음.
 */

@Configuration
public class SecurityConfig{
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails user1 = User
                .withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails user2 = User
                .withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
            http
                .authorizeHttpRequests((request) ->
                        request.requestMatchers("/design", "orders").hasRole("USER")
                                .requestMatchers("/", "/**").permitAll()
                ).httpBasic(Customizer.withDefaults());

            return http.build();
    }


}
