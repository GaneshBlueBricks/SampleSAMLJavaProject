package com.samlexample.demo.controller;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletResponse;

@Controller
public class AuthController {

	@Autowired
	private MylocalHelper myhelper;

	@Value("${saml.idp.sso.url}")
	private String idpSsoUrl;
	
	@Value("${base.url}")
	private String axiomBaseUrl;

	
	@GetMapping("/login")
	public String login() {
		return "login"; // Returns the login Thymeleaf page
	}

	@PostMapping("/login")
	public String login(Model model) {
		try {
			String requestID = "id-" + UUID.randomUUID().toString();
			// Generate SAML AuthnRequest
			String samlRequest = myhelper.createSAMLRequest(); // Base64-encoded SAMLRequest
			String relayState = "someRelayState"; // Optional RelayState
			model.addAttribute("samlRequest", samlRequest);
			model.addAttribute("relayState", "");
			model.addAttribute("entityEndpoint", idpSsoUrl); // Add entity endpoint
			model.addAttribute("type", "SAMLRequest"); // Add type
			model.addAttribute("idpSsoUrl", idpSsoUrl); // URL to the IdP
			model.addAttribute("requestID", requestID); // URL to the IdP

			return "samlPostForm"; // Renders a form that posts the SAMLRequest
		} catch (Exception e) {
			e.printStackTrace();
			model.addAttribute("errorMessage", "Error initiating SAML login: " + e.getMessage());
			return "login1"; // Show the login page with an error message
		}
	}
		
	@GetMapping("/redirectLogin")
	public void redirectLogin(Model model, HttpServletResponse response) {
	    try {
	        // Generate SAML AuthnRequest
	        String samlRequest = myhelper.createSAMLRedirectRequests(); // URL-encoded SAMLRequest
//	        String relayState = "someRelayState"; // Optional RelayState
	        String requestID = "id-" + UUID.randomUUID().toString();

	        // Build the full URL for the SAML request (Redirect binding)
	        String redirectUrl = idpSsoUrl + "?SAMLRequest=" + samlRequest;
	        
	        // Redirect to the IdP with the SAML request
	        response.sendRedirect(redirectUrl);

//	        return null; // No view to render as we are redirecting
	        model.addAttribute("samlRequest", samlRequest);
			model.addAttribute("relayState", "");
			model.addAttribute("entityEndpoint", idpSsoUrl); // Add entity endpoint
			model.addAttribute("type", "SAMLRequest"); // Add type
			model.addAttribute("idpSsoUrl", idpSsoUrl); // URL to the IdP
			model.addAttribute("requestID", requestID); // URL to the IdP

//			return "samlRedirect";

	    } catch (Exception e) {
	        e.printStackTrace();
	        model.addAttribute("errorMessage", "Error initiating SAML redirect login: " + e.getMessage());
//	        return "login1"; // Show the login page with an error message
	    }
	}

//	@PostMapping("/login")
//	public String login(Model model) {
//		System.out.println("Login method invoked");
//		 try {
//		        // Create and encode SAML AuthnRequest
//		        String samlRequest = myhelper.createSAMLRequest(); // Implement this method
//		        
//		        // Define the IdP SSO URL (from your properties or configuration)
//		        String idpSSOUrl = "https://saml.passwordless4u.com/idp/login/6e80eafe-fd80-4686-a8b0-9a60307255bf";
//
//		        // Add the encoded SAML request as a query parameter (usually named "SAMLRequest")
//		        String redirectUrl = idpSSOUrl + "?SAMLRequest=" + URLEncoder.encode(samlRequest, StandardCharsets.UTF_8.toString());
//
//		        // Optionally, include a RelayState parameter
//		        String relayState = "someRelayState"; // Define this if needed
//		        redirectUrl += "&RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8.toString());
//
//		        // Redirect to the IdP SSO URL with the SAMLRequest
//		        return "redirect:" + redirectUrl;
//		    } catch (Exception e) {
//		        e.printStackTrace();
//		        model.addAttribute("errorMessage", "Error initiating SAML login: " + e.getMessage());
//		        return "login"; // Show the login page with error message
//		    }
//	}

//
//	@PostMapping("/login")
//	public String initiateSAMLAuthentication(HttpServletResponse response) {
//		// Create SAML request and redirect to IdP
//		String samlRequest = myhelper.createSAMLRequest(); // Implement SAML request creation
//		return "redirect:" + idpSsoUrl + "?SAMLRequest=" + samlRequest;
//	}

	@PostMapping("/acs")
	public String handleSAMLResponse(@RequestParam Map<String, String> params, Model model) {
		try {
			String samlResponse = params.get("SAMLResponse");
			// Validate and process SAML response
			// Validate and process the SAML response
			Map<String, String> response = MylocalHelper.decodeSamlResponse(samlResponse); // Implement this method to
																							// parse the response
//			boolean isValid = myhelper.validateSAMLResponse(response);
//			System.out.println(response);
			if (true) {
				// For development purposes, create a default user
				String username = "Ganesh"; // Default username
				String password = ""; // Default password (empty for now)

				// Define the authorities for the user (you may customize these)
				List<GrantedAuthority> authorities = new ArrayList<>();
				authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // Add a default role

				// Create UserDetails object
				UserDetails userDetails = new User(username, password, true, false, false, false, authorities);

				// Create an authentication token
				Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null,
						userDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication); // Set authentication in the
																						// security context

				// Add the response map to the model
				model.addAttribute("samlResponseMap", response);

				return "dashboard"; // Redirect to secured page
			} else {
				model.addAttribute("errorMessage", "Authentication failed: Invalid SAML response.");
				return "error"; // Redirect to error page
			}
		} catch (Exception e) {
			model.addAttribute("errorMessage", "Authentication failed: " + e.getMessage());
			return "error"; // Redirect to error page
		}
	}

	@GetMapping("/dashboard")
	public String dashboard() {
		return "dashboard"; // Returns the secured dashboard page
	}

	@PostMapping("/logoout")
	public String logout(@RequestParam String accessToken, @RequestParam String userId) {
		String baseUrl = axiomBaseUrl+"/v1/saml/userLogout";

		// Create a RestTemplate or use WebClient to call the logout API
		RestTemplate restTemplate = new RestTemplate();

		// Prepare the request parameters
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("accessToken", accessToken);
		params.add("userId", userId);
		params.add("accountId", null);

		// Call the logout API
		ResponseEntity<String> responseEntity = restTemplate.postForEntity(baseUrl, params, String.class);

		// Check if the response is successful
		if (responseEntity.getStatusCode() == org.springframework.http.HttpStatus.OK
				&& responseEntity.getBody() != null) {
			String body = responseEntity.getBody();
			try {
				if (body != null) {
					ObjectMapper objectMapper = new ObjectMapper();
					Map<String, Object> responseMap = objectMapper.readValue(body, Map.class);
					// Extract user data from the response
					int resultCode = (int) responseMap.get("resultCode");
					if (resultCode == 0) {
						return "login";
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		// Handle logout failure scenario
		return "redirect:/error"; // Redirect to an error page or handle it accordingly
	}

}
