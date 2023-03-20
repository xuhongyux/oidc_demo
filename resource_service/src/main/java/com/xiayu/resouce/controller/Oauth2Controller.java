package com.xiayu.resouce.controller;

import com.gargoylesoftware.htmlunit.BrowserVersion;
import com.gargoylesoftware.htmlunit.CookieManager;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.xiayu.resouce.config.ConfigProperties;
import com.xiayu.resouce.config.ReflectionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.cloud.context.refresh.ContextRefresher;
import org.springframework.web.servlet.view.tiles3.SpringWildcardServletTilesApplicationContext;


/**
 * @author xuhongyu
 * @create 2022-04-25 2:38 下午
 */

@RestController
public class Oauth2Controller {

    private static final String COOKIE = "Cookie";

    @Autowired
    InMemoryClientRegistrationRepository inMemoryClientRegistrationRepository;


    @Autowired
    ConfigProperties configProperties;

    @GetMapping(value = "oauth/logout")
    public Boolean logoutOauth2CodeOkta(HttpServletRequest httpServletRequest) throws URISyntaxException {
        HttpHeaders headers = new HttpHeaders();
        String uriStr = "http://localhost:" + 8081 + "/logout";
        String header = httpServletRequest.getHeader(HttpHeaders.COOKIE);
        List<String> cookies = new ArrayList<>();
        cookies.add(header);
        List<String> referer = new ArrayList<>();
        referer.add(uriStr);
        headers.put(HttpHeaders.COOKIE, cookies);
        headers.put(HttpHeaders.REFERER, referer);
        try {

            URI uri = new URI(uriStr);
            MultiValueMap<String, String> stringMultiValueMap = new LinkedMultiValueMap<>();

            RequestEntity requestEntity = new RequestEntity<>(stringMultiValueMap, headers, HttpMethod.GET, uri);
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity exchange = restTemplate.exchange(requestEntity, String.class);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    @GetMapping(value = "oauth/loadConfig")
    public String loadConfig(HttpServletResponse response, UserBo userBo) {

        OAuth2ClientProperties  oauth2ClientProperties = new OAuth2ClientProperties();

        OAuth2ClientProperties.Registration oAuth2ClientPropertiesRegistration = new OAuth2ClientProperties.Registration();
        oAuth2ClientPropertiesRegistration.setClientId("oidcOauth");
        oAuth2ClientPropertiesRegistration.setClientSecret("secret");
        oAuth2ClientPropertiesRegistration.setAuthorizationGrantType("authorization_code");
        HashSet<String> scopes = new HashSet<>();
        scopes.add("login");
        oAuth2ClientPropertiesRegistration.setScope(scopes);
        oAuth2ClientPropertiesRegistration.setRedirectUri("http://192.168.1.111:8081/login/oauth2/code/localJdbc");

        HashMap<String, OAuth2ClientProperties.Registration> registrationMap = new HashMap<>();
        registrationMap.put("load",oAuth2ClientPropertiesRegistration);

        OAuth2ClientProperties.Provider oAuth2ClientPropertiesProvider = new OAuth2ClientProperties.Provider();
        oAuth2ClientPropertiesProvider.setTokenUri("http://localhost:8082/oauth/token");
        oAuth2ClientPropertiesProvider.setAuthorizationUri("http://localhost:8082/oauth/authorize");
        oAuth2ClientPropertiesProvider.setUserInfoUri("http://localhost:8082/userinfo");
        oAuth2ClientPropertiesProvider.setUserNameAttribute("username");


        HashMap<String, OAuth2ClientProperties.Provider> providerMap = new HashMap<>();
        providerMap.put("load",oAuth2ClientPropertiesProvider);
        try {
            ReflectionUtil.setValue(oauth2ClientProperties, "registration", registrationMap);
            ReflectionUtil.setValue(oauth2ClientProperties, "provider", providerMap);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        List<ClientRegistration> registrations = new ArrayList<>(
                OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(oauth2ClientProperties).values());
        Map<String, ClientRegistration> clientRegistrationHashMap = new HashMap<>();

        Iterator<ClientRegistration> iterator = inMemoryClientRegistrationRepository.iterator();
        while (iterator.hasNext()){
            ClientRegistration next = iterator.next();
            clientRegistrationHashMap.put(next.getRegistrationId(),next);
        }

        for (ClientRegistration registration : registrations) {
            clientRegistrationHashMap.put(registration.getRegistrationId(),registration);
        }

        try {
            ReflectionUtil.setValue(inMemoryClientRegistrationRepository, "registrations", clientRegistrationHashMap);
        } catch (NoSuchFieldException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        return null;
    }



    @GetMapping(value = "oauth/login")
    public String loginOauth2CodeOkta(HttpServletResponse response) {
        WebClient webClient = new WebClient(BrowserVersion.CHROME);
        String userPassword = "xia:123";
        byte[] encode = Base64.getEncoder().encode(userPassword.getBytes());
        StringBuilder authorizationValue = new StringBuilder();
        authorizationValue.append(BasicAuthenticationConverter.AUTHENTICATION_SCHEME_BASIC);
        authorizationValue.append(" ");
        authorizationValue.append(new String(encode));
        webClient.addRequestHeader("Authorization", authorizationValue.toString());
        try {
            HtmlPage page = webClient.getPage("http://192.168.1.110:8081/user/123");
            HtmlAnchor proxverseOauth2 = page.getAnchorByHref("/oauth2/authorization/localJdbc");
            HtmlPage click = proxverseOauth2.click();
            List<DomElement> scopeLoginDems = click.getElementsByName("scope.login");
            if (scopeLoginDems.size() > 0) {
                DomElement scopeLoginDem = scopeLoginDems.get(0);
                scopeLoginDem.click();

                List<DomElement> authorizes = click.getElementsByName("authorize");
                if (authorizes.size() > 0) {
                    DomElement domElement = authorizes.get(0);
                    domElement.click();
                }
            }

            CookieManager cookieManager = webClient.getCookieManager();
            Set<com.gargoylesoftware.htmlunit.util.Cookie> cookies = cookieManager.getCookies();
            for (com.gargoylesoftware.htmlunit.util.Cookie cookie : cookies) {
                Cookie cookieJavax = new Cookie(cookie.getName(), cookie.getValue());
                cookieJavax.setPath(cookie.getPath());
                cookieJavax.setDomain(cookie.getDomain());
                response.addCookie(cookieJavax);
            }
            System.out.println(page.toString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return "登陆成功";
    }

    private String clientId = "client";
    private String redirectUri = "http://localhost:8081/login/oauth2/code/prx";
    private String authorizationUrl = "http://192.168.124.6:8080/oauth/authorize";

    private String getAuthorizationUrl() {

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("response_type", "code");
        queryParams.put("client_id", clientId);
        queryParams.put("scope", "login");
        queryParams.put("state", DEFAULT_STATE_GENERATOR.generateKey());
        queryParams.put("redirect_uri", redirectUri);
        queryParams.put("nonce", builderNonceHash());

        StringBuilder uriBuilder = new StringBuilder();
        uriBuilder.append(authorizationUrl);
        uriBuilder.append('?');

        StringBuilder queryBuilder = new StringBuilder();
        queryParams.forEach((name, value) -> {
            if (org.springframework.util.StringUtils.isEmpty(value)) {
                if (queryBuilder.length() != 0) {
                    queryBuilder.append('&');
                }
                queryBuilder.append(name);
            } else {

                if (queryBuilder.length() != 0) {
                    queryBuilder.append('&');
                }
                queryBuilder.append(name);
                if (value != null) {
                    queryBuilder.append('=').append(value.toString());
                }
            }
        });
        return uriBuilder.append(queryBuilder).toString();
    }


    private String builderNonceHash() {
        try {
            String nonce = DEFAULT_SECURE_KEY_GENERATOR.generateKey();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
            String nonceHash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            return nonceHash;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private static final StringKeyGenerator DEFAULT_SECURE_KEY_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

    private UserBo analysisAuthorize(String authorize) {
        UserBo analysisUserInfo = new UserBo();
        authorize = authorize.trim();
        if (!org.springframework.util.StringUtils.startsWithIgnoreCase(authorize, AUTHENTICATION_SCHEME_BASIC)) {
            return analysisUserInfo;
        }

        if (authorize.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
            throw new BadCredentialsException("Empty basic authentication token");
        }

        byte[] base64Token = authorize.substring(6).getBytes(StandardCharsets.UTF_8);
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Token);
        } catch (IllegalArgumentException e) {
            throw new BadCredentialsException(
                    "Failed to decode basic authentication token");
        }

        String token = new String(decoded, StandardCharsets.UTF_8);

        int delim = token.indexOf(":");

        if (delim == -1) {
            throw new BadCredentialsException("Invalid basic authentication token");
        }
        analysisUserInfo.setName(token.substring(0, delim));
        analysisUserInfo.setPassword(token.substring(delim + 1));
        return analysisUserInfo;
    }

}
