/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.function.Function;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.val;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.util.matcher.RequestMatcher;
import sample.jose.Jwks;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {


  public AuthorizationServerConfig(){
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
        new OAuth2AuthorizationServerConfigurer<>();
    RequestMatcher endpointsMatcher = authorizationServerConfigurer
        .getEndpointsMatcher();

    Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
      OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
      JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
      boolean isGa4GhPassportToken = principal.getAuthorities().stream()
          .anyMatch(a ->a.getAuthority().equalsIgnoreCase("scope_ga4gh_passport_v1"));

      if (isGa4GhPassportToken) {
        val claims = new HashMap<String, Object>();
        JsonNode rootNode = null;
        try {
          rootNode = new ObjectMapper().readValue("{\n" +
              "        \"iat\": 1655923523,\n" +
              "        \"exp\": 1687459492,\n" +
              "        \"ga4gh_visa_v1\": {\n" +
              "            \"type\": \"ControlledAccessGrants\",\n" +
              "            \"asserted\": 1655923523,\n" +
              "            \"value\": \"https://example-institute.org/datasets/710\",\n" +
              "            \"source\": \"https://grid.ac/institutes/grid.0000.0a\",\n" +
              "            \"by\": \"dac\"\n" +
              "        }\n" +
              "    }", JsonNode.class);
        } catch (JsonProcessingException e) {
          throw new RuntimeException();
        }
        claims.put("ga4gh_passport_v1", rootNode);
        claims.putAll(principal.getTokenAttributes());
        return new OidcUserInfo(claims);
      }
      return new OidcUserInfo(principal.getToken().getClaims());
    };

    http
        .requestMatcher(endpointsMatcher)
        .authorizeRequests(authorizeRequests ->
            authorizeRequests.anyRequest().authenticated()
        )
        .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        .apply(authorizationServerConfigurer)
        .oidc(x -> {
          x.userInfoEndpoint(u -> {
            u.userInfoMapper(userInfoMapper);
          });
        });

    http
        // https://github.com/spring-projects/spring-authorization-server/issues/521
        .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
        .apply(authorizationServerConfigurer);

//        .apply(new FederatedIdentityConfigurer())
        ;
    return http.formLogin(Customizer.withDefaults()).build();
  }


  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
    return new FederatedIdentityIdTokenCustomizer();
  }

  // @formatter:off
  @Bean
  public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("client")
        .clientSecret("{noop}secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://127.0.0.1:7000/login/oauth2/code/messaging-client-oidc")
        .redirectUri("http://127.0.0.1:7000/code")
        .redirectUri("http://test-ui:7000/code")
        .redirectUri("http://test-ui:7000/authorized")
        .scope(OidcScopes.OPENID)
        .scope("message.read")
        .scope("message.write")
        .scope("ga4gh_passport_v1")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .build();

    RegisteredClient keycloak = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("keycloak")
        .clientSecret("{noop}secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        .redirectUri("http://localhost:8083/auth/realms/master/broker/ga4gh-broker/endpoint")
        .redirectUri("http://keycloak:8083/auth/realms/master/broker/ga4gh-broker/endpoint")
        .scope(OidcScopes.OPENID)
        .scope("ga4gh_passport_v1")
        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
        .build();

    // Save registered client in db as if in-memory
    JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
    registeredClientRepository.save(registeredClient);
    registeredClientRepository.save(keycloak);

    return registeredClientRepository;
  }
  // @formatter:on

  @Bean
  public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
  }

  @Bean
  public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
    return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
  }

  @Bean
  JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = Jwks.generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  public ProviderSettings providerSettings() {
    return ProviderSettings.builder().issuer("http://localhost:9000").build();
  }

  @Bean
  public EmbeddedDatabase embeddedDatabase() {
    // @formatter:off
    return new EmbeddedDatabaseBuilder()
        .generateUniqueName(true)
        .setType(EmbeddedDatabaseType.H2)
        .setScriptEncoding("UTF-8")
        .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
        .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
        .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
        .build();
    // @formatter:on
  }

}
