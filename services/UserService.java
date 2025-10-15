@Service @RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UsersRepository usersRepository;
   
   //metodo e propriedades ja criado

   // adicionar apenas loadUserByUsername

    

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<Users> userExists = usersRepository.findUserByEmail(email);

        if (userExists.isPresent()) {
            Users user = userExists.get();
            List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

            return new org.springframework.security.core.userdetails.User(
                    user.getEmail(),
                    user.getPassword(),
                    authorities
            );
        }

    }
}