package overture.bio.ego.keycloak;

import javax.validation.constraints.NotNull;

public class CreateUserRequest {
  @NotNull public String email;
  @NotNull public String firstName;
  @NotNull public String lastName;
  @NotNull public String providerType;
  @NotNull public String providerSubjectId;
  @NotNull public String providerAccessToken;
  @NotNull public boolean includeGa4ghPermissions;
}