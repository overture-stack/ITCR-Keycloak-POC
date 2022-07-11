package sample.config;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * @author Steve Riesenberg
 * @since 0.2.3
 */
@Controller
public class LoginController {

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/id")
	@ResponseBody
	public Object identity(OAuth2AuthenticationToken token) {
		return token;
	}

}