package com.xiayu.resouce.config;

import lombok.Data;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author xuhongyu
 * @create 2023-03-17 10:17
 */


@Configuration
@ConfigurationPropertiesScan
@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class Oauth2ClientConfig {

    private Map<String,LinkedHashMap> provider;

    private Map<String,LinkedHashMap> registration;

    public Map<String, LinkedHashMap> getRegistration() {
        return registration;
    }

    public void setRegistration(Map<String, LinkedHashMap> registration) {
        this.registration = registration;
    }

    public Map<String, LinkedHashMap> getProvider() {
        return provider;
    }

    public void setProvider(Map<String, LinkedHashMap> provider) {
        this.provider = provider;
    }
}
