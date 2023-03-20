package xiayu.authorizeJdbc.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import xiayu.authorizeJdbc.controller.CustomerUserDetails;

import java.util.ArrayList;
import java.util.List;

/**
 * @author xuhongyu
 * @create 2022-04-26 1:45 下午
 */

@Service
public class UserDetailsServiceConfig implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public CustomerUserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
        // 设置用户权限，所有用户都有user权限
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("USER"));
        CustomerUserDetails customerUserDetails = new CustomerUserDetails();
        customerUserDetails.setId("1");
        customerUserDetails.setPassword(passwordEncoder.encode("123"));
        customerUserDetails.setUsername(userName);
        customerUserDetails.setEnabled(true);
        customerUserDetails.setAccountNonExpired(true);
        customerUserDetails.setAccountNonLocked(true);
        customerUserDetails.setAuthorities(grantedAuthorities);
        customerUserDetails.setGroupId(1);

        return customerUserDetails;
    }



}
