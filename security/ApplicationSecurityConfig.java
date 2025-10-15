@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApplicationSecurityConfig {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final UsersRepository usersRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        CustomAuthFilter customAuthFilter = new CustomAuthFilter(authenticationManager, usersRepository);
        customAuthFilter.setFilterProcessesUrl("/login"); 

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/login/**" , "/add").permitAll()
                .anyRequest().authenticated()
            )
            .addFilter(customAuthFilter)
            .addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        // nao salvamos a senha encriptada ainda entao passamos o noOpPasswordEncoder para nao validar
        return http
            .getSharedObject(AuthenticationManagerBuilder.class)
            .userDetailsService(userService)
            .passwordEncoder(org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance()) 
            .and()
            .build();
    }
}