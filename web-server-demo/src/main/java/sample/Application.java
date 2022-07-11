package sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class Application {

  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

  @Bean
  public WebClient webClient(ClientRegistrationRepository clientRegistrationRepository, OAuth2AuthorizedClientService authorizedClientService) {

    AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
        new AuthorizedClientServiceOAuth2AuthorizedClientManager(clientRegistrationRepository, authorizedClientService);

    manager.setAuthorizedClientProvider(new DelegatingOAuth2AuthorizedClientProvider(
        new RefreshTokenOAuth2AuthorizedClientProvider(),
        new ClientCredentialsOAuth2AuthorizedClientProvider()));

    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(manager);
    oauth2.setDefaultClientRegistrationId("keycloak");

    return WebClient.builder()
        .filter(oauth2)
        .apply(oauth2.oauth2Configuration())
        .build();
  }
}