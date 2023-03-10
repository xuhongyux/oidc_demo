package com.xiayu.authorize.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

/**
 * @author xuhongyu
 * @create 2023-03-10 15:39
 */

@Configuration
@EnableAuthorizationServer
@EnableResourceServer
public class AuthorizationConfig extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private PasswordEncoder passwordEncoder;


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许表单提交
        security.allowFormAuthenticationForClients()
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory()
                //客户端唯一标识（client_id）
                .withClient("client")
                //客户端的密码(client_secret)，这里的密码应该是加密后的
                .secret(passwordEncoder.encode("secret"))
                //授权模式标识
                .authorizedGrantTypes("authorization_code")
                //作用域
                .scopes("openid","login")
                //回调地址
                .redirectUris("http://192.168.1.110:8081/login/oauth2/code/prx");
    }
}
