package tacos.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
/*import org.springframework.security.core.userdetails.User;*/
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
/*import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;*/
import org.springframework.security.web.SecurityFilterChain;

import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tacos.User;
import tacos.data.UserRepository;

/*import javax.sql.DataSource;*/

/*책의 실습에는 Spring Security 버전이  낮기 때문에 해당 클래스는 WebSecurityConfigurerAdapter 클래스를 상속받아 구현하였지만,
      현재 Spring Security 6.3.3 기준 해당 클래스는 지원 중단 되었고 SecurityFilterChain을 Bean으로 등록하여 사용함
      그에 맞게 설정들을 서칭하여 책의 설정들을 최신 버전에 맞게 변경하였음.
 */

@Configuration
public class SecurityConfig{
    /*private final DataSource dataSource;

    public SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }*/

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepo){

        return new UserDetailsService(){
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                User user = userRepo.findByUsername(username);
                if(user!=null){
                    return user;
                }
                throw new UsernameNotFoundException(
                        "User '" + username + "' not found"
                );
            }
        };
    }
    //Jdbc
    /*
    @Bean
    public UserDetailsService userDetailsService(){
        JdbcUserDetailsManager jdbcUserDetailManager = new JdbcUserDetailsManager(dataSource);

        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("user2")
                .password(passwordEncoder().encode("password2"))
                .roles("USER")
                .build();

        jdbcUserDetailManager.createUser(user1);
        jdbcUserDetailManager.createUser(user2);

        return jdbcUserDetailManager;
    }*/
    // ImMemory
    /*@Bean
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
    }*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeHttpRequests((request) ->
                        request.requestMatchers("/design", "/orders").hasRole("USER")
                                .anyRequest().permitAll()
                )
                .formLogin((login) -> login.loginPage("/login").defaultSuccessUrl("/"))
                .logout((logout) -> logout.logoutSuccessUrl("/"))
                .csrf((csrf) -> csrf.
                        ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                .headers((headers) -> headers
                        .addHeaderWriter(new XFrameOptionsHeaderWriter(
                                XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN
                        )));
        return http.build();
    }


}