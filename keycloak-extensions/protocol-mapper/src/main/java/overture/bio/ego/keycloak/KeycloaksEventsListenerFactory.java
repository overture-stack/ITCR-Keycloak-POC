package overture.bio.ego.keycloak;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class KeycloaksEventsListenerFactory implements EventListenerProviderFactory {


  @Override
  public KeycloaksEventsListener create(KeycloakSession keycloakSession) {
    return new KeycloaksEventsListener(keycloakSession);
  }

  @Override
  public void init(Config.Scope scope) {

  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

  }

  @Override
  public void close() {

  }

  @Override
  public String getId() {
    return "ego_events_listener";
  }
}