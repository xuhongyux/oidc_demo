package com.xiayu.resouce;

import com.xiayu.resouce.config.Oauth2ClientConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;



/**
 * @author xuhongyu
 * @create 2023-03-10 15:00
 */

@EnableConfigurationProperties({Oauth2ClientConfig.class})
@SpringBootApplication
public class ResourceApplication {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(ResourceApplication.class);
        application.run(args);
    }
}
