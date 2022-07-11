package overture.bio.ego.keycloak;


import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;

import java.util.Map;
//https://github.com/adwait-thattey/keycloak-event-listener-spi/tree/master/sample_event_listener
public class KeycloaksEventsListener implements EventListenerProvider {

  KeycloakSession session;
  public KeycloaksEventsListener(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void onEvent(Event event) {
    System.out.println("Event Occurred:" + toString(event));
  }

  @Override
  public void onEvent(AdminEvent event, boolean includeRepresentation) {
    System.out.println("Admin Event Occurred:" + event.toString());
  }

  @Override
  public void close() {

  }

  private String toString(Event event) {
    StringBuilder sb = new StringBuilder();
    sb.append("type=");
    sb.append(event.getType());
    sb.append(", realmId=");
    sb.append(event.getRealmId());
    sb.append(", clientId=");
    sb.append(event.getClientId());
    sb.append(", userId=");
    sb.append(event.getUserId());
    sb.append(", ipAddress=");
    sb.append(event.getIpAddress());
    if (event.getError() != null) {
      sb.append(", error=");
      sb.append(event.getError());
    }
    if (event.getDetails() != null) {
      for (Map.Entry<String, String> e : event.getDetails().entrySet()) {
        sb.append(", ");
        sb.append(e.getKey());
        if (e.getValue() == null || e.getValue().indexOf(' ') == -1) {
          sb.append("=");
          sb.append(e.getValue());
        } else {
          sb.append("='");
          sb.append(e.getValue());
          sb.append("'");
        }
      }
    }
    return sb.toString();
  }
}