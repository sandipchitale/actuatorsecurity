package sandipchitale.actuatorsecurity;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@EnableWebSecurity
public class ActuatorsecurityApplication {

	@RestController
	public static class IndexController {

	    @GetMapping("/")
	    public String index() {
	        return "Hello World";
	    }
	}

	@Bean
	SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.securityMatcher(EndpointRequest.toAnyEndpoint())
				.authorizeHttpRequests(authorizeHttpRequests ->
								authorizeHttpRequests
										.anyRequest()
										.permitAll());
		return httpSecurity.build();
	}

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity
				.authorizeHttpRequests(authorizeHttpRequests ->
								authorizeHttpRequests
										.anyRequest()
										.fullyAuthenticated())
				.formLogin(formLogin -> {
					formLogin.permitAll();
				});
		return httpSecurity.build();
	}

	public static void main(String[] args) {
		SpringApplication.run(ActuatorsecurityApplication.class, args);
	}

}
