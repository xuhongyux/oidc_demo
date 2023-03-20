package xiayu.authorizeJdbc.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.sql.DataSource;

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

    @Bean
    @Primary
    @ConfigurationProperties(prefix = "spring.datasource")
    public DataSource dataSource() {
        // 配置数据源（注意，使用的是 HikariCP 连接池），以上注解是指定数据源，否则会有冲突
        return DataSourceBuilder.create().build();
    }

    @Bean
    public ClientDetailsService jdbcClientDetails() {
        return new JdbcClientDetailsService(dataSource());
    }


    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        //允许表单提交
        security.allowFormAuthenticationForClients()
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 配置客户端
        clients.withClientDetails(jdbcClientDetails());
    }
}
