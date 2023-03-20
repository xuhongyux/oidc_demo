package com.xiayu.authorize.service;

import com.xiayu.authorize.config.DefaultOidcIdTokenValidatorFactory;
import org.apache.tomcat.util.buf.StringUtils;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * @author xuhongyu
 * @create 2023-03-10 17:37
 */

@Service
public class Oauth2Service {


    private final Map<String, JwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

    private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

    private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";

    private static final StringKeyGenerator DEFAULT_SECURE_KEY_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    private static final StringKeyGenerator DEFAULT_STATE_GENERATOR = new Base64StringKeyGenerator(Base64.getUrlEncoder());


    private Function<ClientRegistration, JwsAlgorithm> jwsAlgorithmResolver = (
            clientRegistration) -> SignatureAlgorithm.RS256;

    private Function<ClientRegistration, OAuth2TokenValidator<Jwt>> jwtValidatorFactory = new DefaultOidcIdTokenValidatorFactory();

    private Function<ClientRegistration, Converter<Map<String, Object>, Map<String, Object>>> claimTypeConverterFactory = (
            clientRegistration) -> DEFAULT_CLAIM_TYPE_CONVERTER;


    private static final ClaimTypeConverter DEFAULT_CLAIM_TYPE_CONVERTER = new ClaimTypeConverter(
            createDefaultClaimTypeConverters());

    private static final Map<JwsAlgorithm, String> JCA_ALGORITHM_MAPPINGS;

    static {
        Map<JwsAlgorithm, String> mappings = new HashMap<>();
        mappings.put(MacAlgorithm.HS256, "HmacSHA256");
        mappings.put(MacAlgorithm.HS384, "HmacSHA384");
        mappings.put(MacAlgorithm.HS512, "HmacSHA512");
        JCA_ALGORITHM_MAPPINGS = Collections.unmodifiableMap(mappings);
    }


    private String registrationId  = "prx";

    private String clientId = "client";

    private String clientSecret = "secret";

    private String authorizationGrantType = "authorization_code";


    private List<String> scopes = new ArrayList<>();


    private String redirectUri = "http://localhost:8081/oauth2/v1/authorize";






    @GetMapping(value = "/oauth2/authorization/okta")
    public String oauth2AuthorizationOkta() {
        scopes.add("openid");
        scopes.add("profile");
        scopes.add("email");
        scopes.add("address");
        scopes.add("phone");
        scopes.add("offline_access");

        StringUtils.join(scopes, ' ');

        String url = "";
        try {
            url = toUrlString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return url;
    }

    private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();


    @GetMapping(value = "/login/oauth2/code/okta")
    public String loginOauth2CodeOkta(@RequestParam String code, @RequestParam String state) throws URISyntaxException {
        //URI uri = new URI("https://dev-50350041.okta.com/oauth2/v1/token");
        URI uri = new URI(redirectUri);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));
        final MediaType contentType = MediaType.valueOf(MediaType.APPLICATION_FORM_URLENCODED_VALUE + ";charset=UTF-8");
        headers.setContentType(contentType);

        String clientCredential = encodeClientCredential(clientId);
        String credentialSecretCredential = encodeClientCredential(clientSecret);

        // ClientRegistration 构建
        String registrationId = "okta";
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientId(clientCredential);
        builder.clientSecret(credentialSecretCredential);
        builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}");
        builder.scope(scopes);
        builder.clientName("");
        builder.authorizationUri("https://localhost:8081/oauth2/v1/authorize");
        builder.tokenUri("https://localhost:8081/oauth2/v1/token");
        builder.jwkSetUri("https://localhost:8081/oauth2/v1/keys");

        ClientRegistration clientRegistration = builder.build();


        headers.setBasicAuth(clientCredential, credentialSecretCredential);

        MultiValueMap<String, String> stringMultiValueMap = new LinkedMultiValueMap<>();
        stringMultiValueMap.add("grant_type", "authorization_code");
        stringMultiValueMap.add("code", code);
        stringMultiValueMap.add("redirect_uri", "http://localhost:8081/login/oauth2/code/okta");

        // 构建restTemplate
        RestTemplate restTemplate = new RestTemplate(
                Arrays.asList(new FormHttpMessageConverter(), new OAuth2AccessTokenResponseHttpMessageConverter()));
        restTemplate.setErrorHandler(new OAuth2ErrorResponseErrorHandler());

        RequestEntity requestEntity = new RequestEntity<>(stringMultiValueMap, headers, HttpMethod.POST, uri);


        ResponseEntity<OAuth2AccessTokenResponse> exchange = restTemplate.exchange(requestEntity, OAuth2AccessTokenResponse.class);
        OAuth2AccessTokenResponse body = exchange.getBody();
        String analysisToken = analysisToken(body, clientRegistration);

        return analysisToken;
    }

    private String analysisToken(OAuth2AccessTokenResponse body, ClientRegistration clientRegistration) {
        JwtDecoder oktaJwtDecoder = jwtDecoders.computeIfAbsent("okta", (key) -> {
            NimbusJwtDecoder jwtDecoder = buildDecoder(clientRegistration);
            jwtDecoder.setJwtValidator(jwtValidatorFactory.apply(clientRegistration));
            Converter<Map<String, Object>, Map<String, Object>> claimTypeConverter = claimTypeConverterFactory
                    .apply(clientRegistration);
            if (claimTypeConverter != null) {
                jwtDecoder.setClaimSetConverter(claimTypeConverter);
            }
            return jwtDecoder;
        });
        Jwt jwt = getJwt(body, oktaJwtDecoder);
        String preferredUsername = jwt.getClaims().get("preferred_username").toString();
        return preferredUsername;
    }


    private Jwt getJwt(OAuth2AccessTokenResponse accessTokenResponse, JwtDecoder jwtDecoder) {
        try {
            Map<String, Object> parameters = accessTokenResponse.getAdditionalParameters();
            return jwtDecoder.decode((String) parameters.get(OidcParameterNames.ID_TOKEN));
        } catch (JwtException ex) {
            OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, ex.getMessage(), null);
            throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), ex);
        }
    }

    private String toUrlString() throws NoSuchAlgorithmException {
        String nonce = DEFAULT_SECURE_KEY_GENERATOR.generateKey();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));

        String nonceHash = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

        String state = DEFAULT_STATE_GENERATOR.generateKey();

        StringBuilder uriBuilder = new StringBuilder();
        uriBuilder.append(redirectUri);
        uriBuilder.append('?');

        Map<String, String> queryParams = new HashMap<>();
        queryParams.put("response_type", "code");
        queryParams.put("client_id", clientId);
        queryParams.put("scope", "openid%20profile%20email%20address%20phone%20offline_access");
        queryParams.put("state", state);
        queryParams.put("redirect_uri", "http://localhost:8081/login/oauth2/code/okta");
        queryParams.put("nonce", nonceHash);

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
        uriBuilder.append(queryBuilder);

        return uriBuilder.toString();
    }


    private static String encodeClientCredential(String clientCredential) {
        try {
            return URLEncoder.encode(clientCredential, StandardCharsets.UTF_8.toString());
        } catch (UnsupportedEncodingException ex) {
            // Will not happen since UTF-8 is a standard charset
            throw new IllegalArgumentException(ex);
        }
    }

    /**
     * 构建解码器
     *
     * @param clientRegistration
     * @return
     */
    private NimbusJwtDecoder buildDecoder(ClientRegistration clientRegistration) {
        JwsAlgorithm jwsAlgorithm = this.jwsAlgorithmResolver.apply(clientRegistration);
        if (jwsAlgorithm != null && SignatureAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
            // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            //
            // 6. If the ID Token is received via direct communication between the Client
            // and the Token Endpoint (which it is in this flow),
            // the TLS server validation MAY be used to validate the issuer in place of
            // checking the token signature.
            // The Client MUST validate the signature of all other ID Tokens according to
            // JWS [JWS]
            // using the algorithm specified in the JWT alg Header Parameter.
            // The Client MUST use the keys provided by the Issuer.
            //
            // 7. The alg value SHOULD be the default of RS256 or the algorithm sent by
            // the Client
            // in the id_token_signed_response_alg parameter during Registration.

            String jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
            if (!org.springframework.util.StringUtils.hasText(jwkSetUri)) {
                OAuth2Error oauth2Error = new OAuth2Error(MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
                        "Failed to find a Signature Verifier for Client Registration: '"
                                + clientRegistration.getRegistrationId()
                                + "'. Check to ensure you have configured the JwkSet URI.",
                        null);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }
            return NimbusJwtDecoder.withJwkSetUri(jwkSetUri).jwsAlgorithm((SignatureAlgorithm) jwsAlgorithm).build();
        }
        if (jwsAlgorithm != null && MacAlgorithm.class.isAssignableFrom(jwsAlgorithm.getClass())) {
            // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
            //
            // 8. If the JWT alg Header Parameter uses a MAC based algorithm such as
            // HS256, HS384, or HS512,
            // the octets of the UTF-8 representation of the client_secret
            // corresponding to the client_id contained in the aud (audience) Claim
            // are used as the key to validate the signature.
            // For MAC based algorithms, the behavior is unspecified if the aud is
            // multi-valued or
            // if an azp value is present that is different than the aud value.
            String clientSecret = clientRegistration.getClientSecret();
            if (!org.springframework.util.StringUtils.hasText(clientSecret)) {
                OAuth2Error oauth2Error = new OAuth2Error(MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
                        "Failed to find a Signature Verifier for Client Registration: '"
                                + clientRegistration.getRegistrationId()
                                + "'. Check to ensure you have configured the client secret.",
                        null);
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }
            SecretKeySpec secretKeySpec = new SecretKeySpec(clientSecret.getBytes(StandardCharsets.UTF_8),
                    JCA_ALGORITHM_MAPPINGS.get(jwsAlgorithm));
            return NimbusJwtDecoder.withSecretKey(secretKeySpec).macAlgorithm((MacAlgorithm) jwsAlgorithm).build();
        }
        OAuth2Error oauth2Error = new OAuth2Error(MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
                "Failed to find a Signature Verifier for Client Registration: '"
                        + clientRegistration.getRegistrationId()
                        + "'. Check to ensure you have configured a valid JWS Algorithm: '" + jwsAlgorithm + "'",
                null);
        throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }



    /**
     * Returns the default {@link Converter}'s used for type conversion of claim values
     * for an {@link OidcIdToken}.
     *
     * @return a {@link Map} of {@link Converter}'s keyed by {@link IdTokenClaimNames
     * claim name}
     */
    public static Map<String, Converter<Object, ?>> createDefaultClaimTypeConverters() {
        Converter<Object, ?> booleanConverter = getConverter(TypeDescriptor.valueOf(Boolean.class));
        Converter<Object, ?> instantConverter = getConverter(TypeDescriptor.valueOf(Instant.class));
        Converter<Object, ?> urlConverter = getConverter(TypeDescriptor.valueOf(URL.class));
        Converter<Object, ?> stringConverter = getConverter(TypeDescriptor.valueOf(String.class));
        Converter<Object, ?> collectionStringConverter = getConverter(
                TypeDescriptor.collection(Collection.class, TypeDescriptor.valueOf(String.class)));
        Map<String, Converter<Object, ?>> converters = new HashMap<>();
        converters.put(IdTokenClaimNames.ISS, urlConverter);
        converters.put(IdTokenClaimNames.AUD, collectionStringConverter);
        converters.put(IdTokenClaimNames.NONCE, stringConverter);
        converters.put(IdTokenClaimNames.EXP, instantConverter);
        converters.put(IdTokenClaimNames.IAT, instantConverter);
        converters.put(IdTokenClaimNames.AUTH_TIME, instantConverter);
        converters.put(IdTokenClaimNames.AMR, collectionStringConverter);
        converters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
        converters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
        converters.put(StandardClaimNames.UPDATED_AT, instantConverter);
        return converters;
    }


    private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
        TypeDescriptor sourceDescriptor = TypeDescriptor.valueOf(Object.class);
        return (source) -> ClaimConversionService.getSharedInstance().convert(source, sourceDescriptor,
                targetDescriptor);
    }
}
