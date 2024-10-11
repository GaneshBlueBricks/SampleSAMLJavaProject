package Services;

import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.zip.Deflater;

import Models.BindingContext;
import Models.CustomTagReplacement;
import Models.IdentityProvider;
import Models.ServiceProviderMetadata;

public class ServiceProvider {

	private ServiceProviderMetadata metadata;

	public ServiceProvider(ServiceProviderMetadata metadata) {
		this.metadata = metadata;
	}

	/**
	 * Generates the login request (AuthnRequest) based on the binding type.
	 *
	 * @param idp                  The IdentityProvider object.
	 * @param binding              The binding type (e.g., "HTTP-Redirect",
	 *                             "HTTP-POST").
	 * @param customTagReplacement Optional custom function to modify the SAML
	 *                             request template.
	 * @return BindingContext containing the SAML request.
	 */
	public BindingContext createLoginRequest(IdentityProvider idp, String binding,
			CustomTagReplacement customTagReplacement) throws Exception {

		String samlRequest = createSAMLRequest(idp, customTagReplacement);

		if ("HTTP-Redirect".equalsIgnoreCase(binding)) {
			return handleHttpRedirectBinding(samlRequest, idp);
		} else if ("HTTP-POST".equalsIgnoreCase(binding)) {
			return handleHttpPostBinding(samlRequest, idp);
		} else {
			throw new IllegalArgumentException("Unsupported binding type: " + binding);
		}
	}

	/**
	 * Creates the SAML AuthnRequest XML string.
	 *
	 * @param idp                  The IdentityProvider object.
	 * @param customTagReplacement Optional custom function to modify the SAML
	 *                             request template.
	 * @return The SAML AuthnRequest XML string.
	 */
	private String createSAMLRequest(IdentityProvider idp, CustomTagReplacement customTagReplacement) {
		String requestID = "id-" + UUID.randomUUID().toString();
		String issueInstant = Instant.now().toString();
		String acsUrl = metadata.getAssertionConsumerServiceUrl(); // SP's ACS URL
		String idpSsoUrl = idp.getSingleSignOnServiceUrl("HTTP-POST"); // IdP's SSO URL

		String samlRequestTemplate = String.format(
				"<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
						+ "ID=\"%s\" Version=\"2.0\" IssueInstant=\"%s\" "
						+ "Destination=\"%s\" AssertionConsumerServiceURL=\"%s\" "
						+ "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
						+ "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">%s</saml:Issuer>"
						+ "<samlp:NameIDPolicy Format=\"%s\" AllowCreate=\"true\"/>" + "</samlp:AuthnRequest>",
				requestID, issueInstant, idpSsoUrl, acsUrl, metadata.getEntityID(), metadata.getNameIDFormat());

		// Allow customization of the SAML request template
		if (customTagReplacement != null) {
			return customTagReplacement.replace(samlRequestTemplate);
		}

		return samlRequestTemplate;
	}

	/**
	 * Handles HTTP-Redirect binding: compress, base64 encode, and optionally sign
	 * the request.
	 *
	 * @param samlRequest The SAML AuthnRequest XML string.
	 * @param idp         The IdentityProvider object.
	 * @return BindingContext containing the HTTP-Redirect URL.
	 */
	private BindingContext handleHttpRedirectBinding(String samlRequest, IdentityProvider idp) throws Exception {
		byte[] deflatedBytes = deflate(samlRequest);
		String base64SamlRequest = Base64.getEncoder().encodeToString(deflatedBytes);

		String redirectUrl = idp.getSingleSignOnServiceUrl("HTTP-Redirect") + "?SAMLRequest=" + base64SamlRequest;

//		if (metadata.isAuthnRequestsSigned()) {
//			String signature = signRequest(redirectUrl, idp.getPrivateKey());
//			redirectUrl += "&Signature=" + signature;
//		}

		return new BindingContext(redirectUrl, "redirect");
	}

	/**
	 * Handles HTTP-POST binding: base64 encode and return an HTML form for
	 * submission.
	 *
	 * @param samlRequest The SAML AuthnRequest XML string.
	 * @param idp         The IdentityProvider object.
	 * @return BindingContext containing the HTML form for HTTP-POST.
	 */
	private BindingContext handleHttpPostBinding(String samlRequest, IdentityProvider idp) {
		String base64SamlRequest = Base64.getEncoder().encodeToString(samlRequest.getBytes());
		String htmlForm = String.format(
				"<form method=\"POST\" action=\"%s\">" + "<input type=\"hidden\" name=\"SAMLRequest\" value=\"%s\"/>"
						+ "<input type=\"submit\" value=\"Submit\"/>" + "</form>",
				idp.getSingleSignOnServiceUrl("HTTP-POST"), base64SamlRequest);

		return new BindingContext(htmlForm, "post");
	}

	/**
	 * Deflates the SAML request for HTTP-Redirect binding.
	 *
	 * @param input The SAML request string.
	 * @return Compressed byte array.
	 */
	private byte[] deflate(String input) throws Exception {
		Deflater deflater = new Deflater(Deflater.DEFLATED, true);
		deflater.setInput(input.getBytes());
		deflater.finish();
		byte[] buffer = new byte[256];
		int length = deflater.deflate(buffer);
		return java.util.Arrays.copyOf(buffer, length);
	}

	/**
	 * Signs the SAML request (HTTP-Redirect binding).
	 *
	 * @param queryString The query string to be signed.
	 * @param privateKey  The private key used for signing.
	 * @return The base64 encoded signature.
	 */
//	private String signRequest(String queryString, PrivateKey privateKey) throws Exception {
//		Signature signature = Signature.getInstance("SHA256withRSA");
//		signature.initSign(privateKey);
//		signature.update(queryString.getBytes());
//		byte[] signatureBytes = signature.sign();
//		return DatatypeConverter.printBase64Binary(signatureBytes);
//	}
}
