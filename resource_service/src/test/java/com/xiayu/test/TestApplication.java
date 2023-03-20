package com.xiayu.test;

import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.WebClient;
import com.xiayu.resouce.controller.UserBo;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;

import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

/**
 * @author xuhongyu
 * @create 2023-03-13 09:57
 */
public class TestApplication {


    public String loginOauth2CodeOktaBody(HttpServletResponse response, UserBo userBo) {
        // 密码加密
        String userPassword = userBo.getName() + ":" + userBo.getPassword();
        WebClient webClient = new WebClient(BrowserVersion.CHROME);
        byte[] encode = Base64.getEncoder().encode(userPassword.getBytes());
        StringBuilder authorizationValue = new StringBuilder();
        authorizationValue.append(BasicAuthenticationConverter.AUTHENTICATION_SCHEME_BASIC);
        authorizationValue.append(" ");
        authorizationValue.append(new String(encode));
        webClient.addRequestHeader("Authorization", authorizationValue.toString());

        return null;
    }
}
