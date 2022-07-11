package overture.bio.ego.keycloak;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.entity.ContentType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

/*
 * Our own example protocol mapper.
 */
public class EgoMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  /*
   * A config which keycloak uses to display a generic dialog to configure the token.
   */
  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  /*
   * The ID of the token mapper. Is public, because we need this id in our data-setup project to
   * configure the protocol mapper in keycloak.
   */
  public static final String PROVIDER_ID = "oidc-ego-mapper";

  static {
    // The builtin protocol mapper let the user define under which claim name (key)
    // the protocol mapper writes its value. To display this option in the generic dialog
    // in keycloak, execute the following method.
    OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
    // The builtin protocol mapper let the user define for which tokens the protocol mapper
    // is executed (access token, id token, user info). To add the config options for the different types
    // to the dialog execute the following method. Note that the following method uses the interfaces
    // this token mapper implements to decide which options to add to the config. So if this token
    // mapper should never be available for some sort of options, e.g. like the id token, just don't
    // implement the corresponding interface.
    OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, EgoMapper.class);
    configProperties.add(new ProviderConfigProperty("EGO_URL", "Ego root url", "ego url to get claims from.", ProviderConfigProperty.STRING_TYPE, "http://localhost:8081/"));
  }

  @Override
  public String getDisplayCategory() {
    return TOKEN_MAPPER_CATEGORY;
  }

  @Override
  public String getDisplayType() {
    return "Ego Token Mapper";
  }

  @Override
  public String getHelpText() {
    return "Adds Ego token claims";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configProperties;
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }

  // although it takes IDToken class, this method is used by all tokens as well access & refresh
  protected void setClaim(IDToken token,
                          ProtocolMapperModel mappingModel,
                          UserSessionModel userSession,
                          KeycloakSession keycloakSession,
                          ClientSessionContext clientSessionCtx) {

    System.out.println("in set claim ==> IDToken ... ");
    // fetch user token claims
    CreateUserRequest request = new CreateUserRequest();
    request.providerSubjectId = userSession.getUser().getId();
    request.providerType = "KEYCLOAK";
    request.email = userSession.getUser().getEmail();
    request.firstName = userSession.getUser().getFirstName();
    request.lastName = userSession.getUser().getLastName();
    HttpClient client = HttpClient.newHttpClient();
    String rootUrl = mappingModel.getConfig().get("EGO_URL");
    HttpRequest httpReq = null;

    // fetch userInfo:
    System.out.println("access token hash => " + token.getAccessTokenHash());

    try {
      String body = new ObjectMapper().writeValueAsString(request);
      System.out.println(">>>>>>>>> json body to ego " + body);
      httpReq = HttpRequest.newBuilder()
          .uri(URI.create(rootUrl + "/users/" + userSession.getUser().getId() + "/claims"))
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .header("Content-Type", ContentType.APPLICATION_JSON.getMimeType())
          .build();
    } catch (JsonProcessingException e) {
      e.printStackTrace();
      throw new RuntimeException();
    }

    try {
      HttpResponse<String> response = client.send(httpReq, HttpResponse.BodyHandlers.ofString());
      String claims = response.body();
      System.out.println(">>>>>>>>>>>>>>>>>> EGO claims " + claims);
      OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
    } catch (InterruptedException | IOException e) {
      e.printStackTrace();
    }
  }
}
