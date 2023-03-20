package com.xiayu.resouce.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.TestAwareAuthenticationSuccessHandler;

/**
 * @author xuhongyu
 * @create 2023-03-12 12:35
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    private String loginRedirect = "http://192.168.1.111:8889/#/check-auth";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        TestAwareAuthenticationSuccessHandler testAwareAuthenticationSuccessHandler = new TestAwareAuthenticationSuccessHandler();
        testAwareAuthenticationSuccessHandler.setDefaultTargetUrl(loginRedirect);
        testAwareAuthenticationSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
        http.authorizeRequests()
                .antMatchers("/oauth/logout", "/oauth/login", "/user/helloWorldPost")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .oauth2Login()
                .successHandler(testAwareAuthenticationSuccessHandler)

        ;
    }
}
