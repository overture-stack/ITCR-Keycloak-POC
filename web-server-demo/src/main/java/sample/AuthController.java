package sample;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.Objects;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

@Controller
public class AuthController {

  @Autowired
  private OAuth2AuthorizedClientService authorizedClientService;

  @Autowired
  WebClient webClient;




  @RequestMapping(method = GET, value = "/profile")
  public String hello(OAuth2AuthenticationToken authentication, Model model, HttpServletResponse response) throws JsonProcessingException {
    if (!(authentication.getPrincipal() instanceof OidcUser)) {
      throw new RuntimeException("Not OpenId user");
    }
    val principal = ((OidcUser) authentication.getPrincipal());
    OAuth2AuthorizedClient client = authorizedClientService
        .loadAuthorizedClient(
            authentication.getAuthorizedClientRegistrationId(),
            authentication.getName());

    Cookie accessTokenCookie = new Cookie("accessToken", client.getAccessToken().getTokenValue());
    Cookie refreshTokenCookie = new Cookie("refreshToken", Objects.requireNonNull(client.getRefreshToken()).getTokenValue());
    Cookie idTokenCookie = new Cookie("identity", principal.getIdToken().getTokenValue());

// disable setSecure while testing locally in browser, or will not show in cookies
// commented out for localhost
//  accessTokenCookie.setSecure(true);
    accessTokenCookie.setHttpOnly(true);
    accessTokenCookie.setPath("/");
    response.addCookie(accessTokenCookie);

    refreshTokenCookie.setHttpOnly(true);
    refreshTokenCookie.setPath("/");
    response.addCookie(refreshTokenCookie);

    idTokenCookie.setHttpOnly(false);
    idTokenCookie.setPath("/");
    response.addCookie(idTokenCookie);

    String userInfoEndpointUri = client.getClientRegistration()
        .getProviderDetails().getUserInfoEndpoint().getUri();

    if (StringUtils.hasText(userInfoEndpointUri)) {
      val userInfo = webClient.get().uri(userInfoEndpointUri)
          .exchangeToMono((x) -> x.bodyToMono(Map.class))
          .block();
      model.addAttribute("name", principal.getGivenName());
      model.addAttribute("claims", principal.getClaims().toString());
      model.addAttribute("userinfo", new ObjectMapper().writeValueAsString(userInfo));
    }

//    val apiKey = webClient.post()
//        .uri("http://localhost:8081/o/api_key?user_id=" + principal.getSubject())
//        .bodyValue(Map.of())
//        .exchangeToMono((x) -> x.bodyToMono(Map.class))
//        .block();

//    model.addAttribute("key", new ObjectMapper().writeValueAsString(apiKey));

    return "profile";
  }

  @RequestMapping(method = GET, value = "/signin")
  public String home(OAuth2AuthenticationToken authentication, Model model, HttpServletResponse response) {
    return "signin";
  }
}
