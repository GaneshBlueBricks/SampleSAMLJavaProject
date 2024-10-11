package com.samlexample.demo.controller;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;
import java.util.zip.Inflater;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import Services.PemUtil;

@Service
public class MylocalHelper { // Class name should start with an uppercase letter

	@Value("${saml.sp.entityId}")
	private String spEntityID;

	@Value("${saml.sp.acsUrl}")
	private String spAcsUrl;
	
	@Value("${saml.idp.sso.url}")
	private String idpSsoUrl;

	@Value("${saml.nameid.format}")
	private String nameIdFormat;

//	@Autowired
//	private SAMLUtils samlUtils;

	public String createSAMLRequest() {
		try {
			// Constructing SAML AuthnRequest manually (without OpenSAML)
			StringBuilder samlRequest = new StringBuilder();

			// Ensure proper spacing and valid XML attributes
			samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ")
					.append("ID=\"id-").append(UUID.randomUUID().toString()).append("\" ").append("Version=\"2.0\" ")
					.append("IssueInstant=\"").append(Instant.now().toString()).append("\" ").append("Destination=\"")
					.append(idpSsoUrl).append("\" ").append("AssertionConsumerServiceURL=\"").append(spAcsUrl)
					.append("\" ")
//					http://localhost:8082/acs\" ")
					.append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">")

					// Correct issuer element
					.append("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">").append(spEntityID)
					.append("</saml:Issuer>")

					// NameIDPolicy with proper attribute formatting
					.append("<samlp:NameIDPolicy Format=\"").append(nameIdFormat).append("\" AllowCreate=\"true\"/>")

					// Close AuthnRequest element
					.append("</samlp:AuthnRequest>");

//			System.out.println("SAML request :" + samlRequest.toString());

			// Encode the request as Base64 and log it for debugging
			String encodedRequest = Base64.getEncoder()
					.encodeToString(samlRequest.toString().getBytes(StandardCharsets.UTF_8));

//			System.out.println("Encoded SAML Request: " + encodedRequest);

			// do not URL encode the Base64-encoded string
			return encodedRequest;

		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Error creating SAML request", e);
		}
	}
	
	private byte[] deflate(String input) throws Exception {
	    Deflater deflater = new Deflater(Deflater.DEFLATED, true);
	    deflater.setInput(input.getBytes());
	    deflater.finish();

	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length());
	    byte[] buffer = new byte[2048]; // Use a larger buffer
	    while (!deflater.finished()) {
	        int length = deflater.deflate(buffer);
	        outputStream.write(buffer, 0, length);
	    }
	    deflater.end();
	    return outputStream.toByteArray();
	}

	private String inflate(byte[] input) throws Exception {
	    Inflater inflater = new Inflater(true);
	    inflater.setInput(input);
	    inflater.finished();

	    ByteArrayOutputStream outputStream = new ByteArrayOutputStream(input.length);
	    byte[] buffer = new byte[2048]; // Use a larger buffer
	    while (!inflater.finished()) {
	        int length = inflater.inflate(buffer);
	        outputStream.write(buffer, 0, length);
	    }
	    inflater.end();
	    return outputStream.toString(); // Convert the output to a String
	}

	public String createSAMLRedirectRequests() {
		try {
//			String redirect = SAMLUtils.redirect();
//			if(redirect!=null) {
////				byte[] deflatedBytes = deflate(samlRequest);
////				String base64SamlRequest = Base64.getEncoder().encodeToString(deflatedBytes);
//				return URLEncoder.encode(redirect,StandardCharsets.UTF_8);
//			}
			
			// Constructing SAML AuthnRequest manually (without OpenSAML)
			StringBuilder samlRequest = new StringBuilder();

			samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ")
		    .append("ID=\"id-").append(UUID.randomUUID().toString()).append("\" ")
		    .append("Version=\"2.0\" ")
		    .append("IssueInstant=\"").append(Instant.now().toString()).append("\" ")
		    .append("Destination=\"").append(idpSsoUrl).append("\" ")
		    .append("AssertionConsumerServiceURL=\"").append(spAcsUrl).append("\" ")
		    .append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">")

		    // Issuer element with properly formatted attributes
		    .append("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">")
		    .append(spEntityID).append("</saml:Issuer>")

		    // NameIDPolicy with proper attribute formatting
		    .append("<samlp:NameIDPolicy Format=\"").append(nameIdFormat).append("\" AllowCreate=\"true\"/>")

		    // Close AuthnRequest element
		    .append("</samlp:AuthnRequest>");

			String samlRequestStr = samlRequest.toString();
			byte[] deflatedBytes = deflate(samlRequestStr);
			String base64SamlRequest = Base64.getEncoder().encodeToString(deflatedBytes);
			
		
//			String encodedRequest = Base64.getEncoder()
//					.encodeToString(samlRequestStr.toString().getBytes(StandardCharsets.UTF_8));

//			String encodedString = "fZJdT8MgFIb%2FSsN9C%2B1wH2RbMl2MS%2FxYtumFN4YCdSQUKoc69dfLWk3mhUvg5vC%2B57wPMAVem4Yt2rC3G%2FXWKgjJR20ssO5ghlpvmeOggVleK2BBsO3i7pYVGWGNd8EJZ9CJ5byDAygftLMoWS1n6EUQKumoJGnBqUxpVQ3TUozKtKpkMS6qnOQTiZIn5SF6Zii2iEaAVq0sBG5DLJGCpjmJa0coG1CWk4wOJ88oWUYWbXnonPsQGmAYHyNmTYxxcF4aBUDbTLgaa9lg4161xYMy%2F9rsULL%2BgbvUVmr7ep6r7EXAbna7dbp%2B2MYGi1%2FWK2ehrZXfKv%2BuhXrc3PZ5YpycDLLRMCvoJLugbEzGBeYC0Hx6zMk6Uj%2F%2F0RonuNk7CL0OGlyrwGXcU3wqn%2FZPeh9DrpZrZ7T4TK6dr3n4nyHP8q6iZVp1UqZqrs1CSh%2FvKLIY4w5XXvGgZqjiBhTC837s388z%2FwY%3D";
////			String keyInfoXml = "<KeyDescriptor use=\"encryption\">"
////					+ "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" + "<ds:X509Data>"
////					+ "<ds:X509Certificate>MIIDwjCCAqqgAwIBAgIOAog5wSBui9gyjesa2rQwDQYJKoZIhvcNAQELBQAwgYExCzAJBgNVBAYTAklOMRQwEgYDVQQIDAtNYWhhcmFzaHRyYTENMAsGA1UEBwwEUHVuZTEUMBIGA1UECgwLYmx1ZS1icmlja3MxETAPBgNVBAsMCFNBTUwtU1NPMSQwIgYDVQQDDBtodHRwczovL3d3dy5ibHVlLWJyaWNrcy5jb20wIBcNMjQwOTI1MTUwOTQzWhgPMjAzNDA5MjMxNTA5NDNaMGMxCzAJBgNVBAYTAklOMQswCQYDVQQIDAJNSDENMAsGA1UEBwwEUHVuZTEUMBIGA1UECgwLQmx1ZS1icmlja3MxETAPBgNVBAsMCFNBTUwtSURQMQ8wDQYDVQQDDAYzYjF6UlQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCuK4oXFI5LA52TrE+/ZE0LvoylcScLbrLQRpVvVmsyBdY28+Osno42A8rBIiX29rzGorYrDoa+jCSIH8us0S6jhT0hCylkxJSE/eNmVbkGfluGme2T53eKVWialnVtn2yq1ab5Aaz5SfV3qtWglyK3yrei9WSoJQnoHJ+q9I+/k/Ov3LDS1rPsceCHfo7qE4huWM54OOD6Sv11mvpo/0Yx1jnImqQxKefptxms3cbVDNwY7n/uJWfZTNoFq/W26RtXKh9ovGkSYBTCVOcu34GzTfuzAH8I3v1J/Scvannvmh1te+dAVdGuErpxfLGAgKrHoq4vF9BdRn5WjV6L+5tnAgMBAAGjUzBRMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFEzVBxlPkyyRxgpRggurKczoPnIoMB8GA1UdIwQYMBaAFEzVBxlPkyyRxgpRggurKczoPnIoMA0GCSqGSIb3DQEBCwUAA4IBAQAV76VGpykraXA+o9aUHUWjbEo6vWZ4NBGkwvY7nAq7nEUMxxWER+ECOECSnGRIDQXB9GvM3KNgtDmxEEROECNgY858CUvumWuET4CgwP+V9oVsCeoQJx2gu13lnGVUCDr4CfUc3kOOnhI6VCalQ7pq+iNWkAZ68R1VV0tSxG3ADJbdF6dW6dIOztOBts8xyUkcTAH2MSxZqAqk1PoSP8ZF510Xv+eFEcDP+YYfOzwmhSHV/Tm8jah5t8OpSc2nm6wcpMT9wqb98S4o3rOG0uX/bpJ8670i2WIet80+mXgRyPVG0hhUZzLQ6D32YWRrwcFsKV03m4gB9opkannN7/Ag</ds:X509Certificate>"
////					+ "</ds:X509Data>" + "</ds:KeyInfo>" + "</KeyDescriptor>";
//			try {
//				// Step 1: URL decode the encoded string
//				String decodedUrl = URLDecoder.decode(encodedString, "UTF-8");
//
//				// Step 2: Base64 decode the URL decoded string
//				byte[] decodedBytes = Base64.getDecoder().decode(decodedUrl);
//
//				String inflate = inflate(decodedBytes);
//				System.out.println("Inflated STring :"+inflate);
//				// Step 3: Extract the public key from the X.509 certificate
////				PublicKey publicKey = extractPublicKeyFromKeyInfo(keyInfoXml);
////
////				// Step 4: Decrypt the data
////				byte[] decryptedData = decrypt(decodedBytes, publicKey);
////
////				// Step 5: Convert decrypted data to XML String
////				String xmlString = new String(decryptedData, "UTF-8");
////				System.out.println("Decrypted XML: " + xmlString);
//
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
			if(base64SamlRequest!=null) {
				return URLEncoder.encode(base64SamlRequest,StandardCharsets.UTF_8);	
			}
//			decoded_url_string = urllib.parse.unquote(encoded_string)
//
//			# Decode the Base64 string
//			decoded_base64_string = base64.b64decode(decoded_url_string)
//
//			# Convert to XML (if it's valid XML)
//			xml_string = decoded_base64_string.decode('utf-8')
//			try {
//				// URL decode the encoded string
//				String decodedUrl = URLDecoder.decode(encodedString, "UTF-8");
//				// Base64 decode the URL decoded string
//				byte[] decodedBytes = Base64.getDecoder().decode(decodedUrl);
//
//				// Optionally, print the length of the byte array
//				System.out.println("Length of decoded bytes: " + decodedBytes.length);
//
//				// Save the binary data to a file (adjust the file path and name as needed)
//				try (FileOutputStream fos = new FileOutputStream("decodedData.bin")) {
//					fos.write(decodedBytes);
//					System.out.println("Binary data written to 'decodedData.bin'");
//				}
////				PrivateKey privateKey = PemUtil.loadPrivateKey("C:/Projects/sampleSaml/encryptKey.pem");
////				
////				byte[] decryptedData = decrypt(decodedBytes, privateKey);
////				String decryptedString = new String(decryptedData, "UTF-8");
//				// Generate RSA keys
//				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
//				keyPairGenerator.initialize(2048);
//				KeyPair keyPair = keyPairGenerator.generateKeyPair();
////				PublicKey publicKey = keyPair.getPublic();
//				PrivateKey privateKey = keyPair.getPrivate();
//				PrivateKey privateKey2 = PemUtil.loadPrivateKey("C:/Projects/sampleSaml/encryptKey.pem");
//				X509Certificate certificate = PemUtil.loadCertificate("C:/Projects/sampleSaml/encryptionCert.pem");
//				PublicKey publicKey2 = certificate.getPublicKey();
//				// Generate AES key
//				SecretKey aesKey = generateAESKey();
//
//				// Encrypt the data using AES
//				byte[] encryptedData = encryptAES(decodedBytes, aesKey);
//
//				// Encrypt the AES key using RSA
//				byte[] encryptedAESKey = encryptRSA(aesKey, publicKey2);
//
//				// Decrypt the AES key using RSA
//				SecretKey decryptedAESKey = decryptRSA(encryptedAESKey, privateKey2);
//
//				// Decrypt the data using the decrypted AES key
//				byte[] decryptedData = decryptAES(encryptedData, decryptedAESKey);
//
//				System.out.println("Decrypted Data: " + new String(decryptedData));
//				String string = new String(decryptedData);
//				System.out.println("Decrypted Data String: " + new String(decryptedData));
//			} catch (UnsupportedEncodingException e) {
//				e.printStackTrace();
//			} catch (IllegalArgumentException e) {
//				System.err.println("Decoding failed: " + e.getMessage());
//			} catch (IOException e) {
//				System.err.println("Error writing to file: " + e.getMessage());
//			}

			// URL encode the Base64-encoded string
//			return URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());

//			try {
//				// Load your public and private keys (ensure they are properly loaded)
//				X509Certificate certificate = PemUtil.loadCertificate("C:/Projects/sampleSaml/encryptionCert.pem");
//				PublicKey publicKey = certificate.getPublicKey();
//				PrivateKey privateKey = PemUtil.loadPrivateKey("C:/Projects/sampleSaml/encryptKey.pem"); // Replace with
//																											// actual
//																											// key
//																											// loading
//
//				// Example data to encrypt
//				String originalData = "Sensitive data to encrypt";
//
//				// Encrypting the data
//				String encryptedData = encryptData(encodedRequest, publicKey);
//				
//				// Print encrypted data and encrypted key
////				System.out.println(
////						"Encrypted Data: " + Base64.getEncoder().encodeToString(encryptedData.getEncryptedData()));
////				System.out.println(
////						"Encrypted Key: " + Base64.getEncoder().encodeToString(encryptedData.getEncryptedKey()));
////
////				// Decrypting the data for demonstration purposes
//				try {
//					String decryptedData = decryptData(encryptedData, privateKey);
//				}catch (Exception e) {
//					// TODO: handle exception
//				}
//				
////				System.out.println("Decrypted Data: " + decryptedData);
//				return encryptedData;
//
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//			String encodedRequest = Base64.getEncoder().encodeToString(samlRequestStr.getBytes(StandardCharsets.UTF_8));
//			String encodedRequestus = Base64.getEncoder().encodeToString(samlRequestStr.getBytes(StandardCharsets.US_ASCII));
//			String encodedRequestusIso = Base64.getEncoder().encodeToString(samlRequestStr.getBytes(StandardCharsets.ISO_8859_1));
//			String encodedRequestusOnlyBytes = Base64.getEncoder().encodeToString(samlRequestStr.getBytes());
//
//			// URL encode the Base64-encoded string
//			
//			byte[] decodedBytes = Base64.getDecoder().decode(encodedRequest);
//            String decodedBase64 = new String(decodedBytes, StandardCharsets.UTF_8);
//            System.out.println("Decoded local Base64 String: " + decodedBase64);
//            
//			String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8);
//
//			// Return the final encoded SAML request
//			
//			// Second String (Base64-encoded)
//            String base64Encoded = "fZJPTwMhEMW%2Fyob7Luy%2FtkvaJtXG2KRq01YPXgwLaElYWBnWqp9euqtJPeiBy%2FDezPvBTIE1uqWLzh%2FMVr52Enz03mgDtL%2BYoc4ZahkooIY1EqjndLe4WdMsIbR11ltuNTqz%2FO9gANJ5ZQ2KVssZehJ1NS7zSsbjTFRxkVV5XOUlj8e8LFNWjyakqlH0IB0EzwyFFsEI0MmVAc%2BMDyWSFXFKYjLZk5JmhJZpUo6KRxQtA4syzPfOg%2FctUIxPEZM2xDhaJ7QEKLqE2wYr0WJtX5TBeZ1%2Bbvco2nzDXSgjlHn5n6seRECv9%2FtNvLnbhQaLH9ZLa6BrpNtJ96a4vN%2BuhzwhTkryZDxKsqJKyoJOyCTDjAOaT085aU%2Fq5t9abTnTBwt%2B0EGLG%2BmZCGeKz%2BXT4UtvQ8jVcmO14h%2FRlXUN838zpEnaV5SIn3splQ1TeiGEC28UWLS2x0snmZcz9Mw0SITnw9jfyzP%2FAg%3D%3D";
//
//            base64Encoded=URLDecoder.decode(base64Encoded, StandardCharsets.UTF_8);
//         // Adjust padding if necessary
//            base64Encoded = base64Encoded.replace('-', '+').replace('_', '/');
//
//            int padding = base64Encoded.length() % 4;
//            if (padding == 2) {
//                base64Encoded += "==";
//            } else if (padding == 3) {
//                base64Encoded += "=";
//            } else if (padding != 0) {
//                // If padding is invalid, print an error and return
//                System.err.println("Invalid Base64 input: padding is incorrect.");
//            }
//
//            try {
//                // Decode Base64
//                decodedBytes = Base64.getDecoder().decode(base64Encoded);
//                String readableString = new String(decodedBytes);
//                System.out.println("Decoded Base64 as byte array length: " + readableString);
//                String decompressedData = decompressGZIP(decodedBytes);
//                System.out.println("Decompressed Data: " + decompressedData);
//                
//            } catch (IllegalArgumentException e) {
//                System.err.println("Failed to decode Base64: " + e.getMessage());
//            }
			return "";
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Error creating SAML redirect request", e);
		}
	}

	// Method to decrypt the data
	public static String decryptData(String encryptedData, PrivateKey privateKey) throws Exception {
		// Step 4: Decrypt the symmetric key using RSA private key
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedKey = rsaCipher.doFinal(encryptedData.getBytes());

		// Step 5: Decrypt the data using the decrypted symmetric key
		SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length, "AES");
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, originalKey);
		byte[] decryptedData = aesCipher.doFinal(encryptedData.getBytes());

		return new String(decryptedData);
	}

//	public static String encryptData(String data, PublicKey publicKey) throws Exception {
//		// Step 1: Generate a symmetric key
//		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//		keyGen.init(256); // Choose key size: 128, 192, or 256 bits
//		SecretKey secretKey = keyGen.generateKey();
//
//		// Step 2: Encrypt the data using AES
//		Cipher aesCipher = Cipher.getInstance("AES");
//		aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
//		byte[] encryptedData = aesCipher.doFinal(data.getBytes());
//
//		// Step 3: Encrypt the symmetric key using RSA
//		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
//		byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());
//
//		// Encode the encrypted data to Base64 and then URL-encode it
//		String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
//		String urlEncodedEncryptedData = URLEncoder.encode(base64EncryptedData, StandardCharsets.UTF_8.toString());
//
//		// Print or return the URL-encoded encrypted data
//		System.out.println("Encrypted Data: " + urlEncodedEncryptedData);
//		return urlEncodedEncryptedData;
////		return new EncryptedData(encryptedData, encryptedKey);
//	}
	
//	public static String encryptData(String data, PublicKey publicKey) throws Exception {
//        // Step 1: Generate a symmetric key
//        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//        keyGen.init(256); // Choose key size: 128, 192, or 256 bits
//        SecretKey secretKey = keyGen.generateKey();
//
//        // Step 2: Create IV and AES cipher in GCM mode
//        byte[] iv = new byte[12];
//        SecureRandom random = new SecureRandom();
//        random.nextBytes(iv); // Generate random IV
//
//        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
//        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(16 * 8, iv));
//
//        // Encrypt the data using AES
//        byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
//
//        // Step 3: Encrypt the symmetric key using RSA
//        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
//        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());
//
//        // Step 4: Encode everything to Base64 and then URL-encode
//        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
//        String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
//        String base64IV = Base64.getEncoder().encodeToString(iv);
//
//        // Return all parts together as a concatenated string
//        String result = String.join(":", base64EncryptedData, base64IV, base64EncryptedKey);
//        return URLEncoder.encode(result, StandardCharsets.UTF_8.toString());
//    }
	public static String encryptData(String data, PublicKey publicKey) throws Exception {
        // Call different encryption methods
        System.out.println("Encryption Methods:");

        // 1. AES GCM Encryption
        String encryptedGCM = encryptAESGCM(data, publicKey);
        System.out.println("1. AES GCM Encrypted Data: " + encryptedGCM);

        // 2. AES CBC Encryption
        String encryptedCBC = encryptAESCBC(data, publicKey);
        System.out.println("2. AES CBC Encrypted Data: " + encryptedCBC);

        // 3. DES Encryption
        String encryptedDES = encryptDES(data, publicKey);
        System.out.println("3. DES Encrypted Data: " + encryptedDES);
        
        return encryptedDES;
        // Additional methods can be added here
    }

    private static String encryptAESGCM(String data, PublicKey publicKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(16 * 8, iv));

        byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
        String base64IV = Base64.getEncoder().encodeToString(iv);

        return URLEncoder.encode(String.join(":", base64EncryptedData, base64IV, base64EncryptedKey), StandardCharsets.UTF_8.toString());
    }

    private static String encryptAESCBC(String data, PublicKey publicKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();

        // Create a random IV
        byte[] iv = new byte[16]; // IV length for AES is 16 bytes
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(iv));

        byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
        String base64IV = Base64.getEncoder().encodeToString(iv);

        return URLEncoder.encode(String.join(":", base64EncryptedData, base64IV, base64EncryptedKey), StandardCharsets.UTF_8.toString());
    }

    private static String encryptDES(String data, PublicKey publicKey) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("DES");
        keyGen.init(56); // DES key size is 56 bits
        SecretKey secretKey = keyGen.generateKey();

        // Create a random IV
        byte[] iv = new byte[8]; // IV length for DES is 8 bytes
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, secretKey, new javax.crypto.spec.IvParameterSpec(iv));

        byte[] encryptedData = desCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = rsaCipher.doFinal(secretKey.getEncoded());

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        String base64EncryptedKey = Base64.getEncoder().encodeToString(encryptedKey);
        String base64IV = Base64.getEncoder().encodeToString(iv);

        return URLEncoder.encode(String.join(":", base64EncryptedData, base64IV, base64EncryptedKey), StandardCharsets.UTF_8.toString());
    }

	private static PublicKey extractPublicKeyFromKeyInfo(String keyInfoXml) throws Exception {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = factory.newDocumentBuilder();
		Document document = builder.parse(new ByteArrayInputStream(keyInfoXml.getBytes()));

		NodeList certList = document.getElementsByTagName("ds:X509Certificate");
		if (certList.getLength() == 0) {
			throw new Exception("Missing X509Certificate in KeyInfo XML");
		}

		String certString = certList.item(0).getTextContent();
		byte[] decodedCert = Base64.getDecoder().decode(certString);

		// Create a CertificateFactory to generate X.509 Certificate
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedCert));

		return cert.getPublicKey();
	}

	private static byte[] decrypt(byte[] encryptedData, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // Use RSA with PKCS1 padding
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encryptedData);
	}

	// Generate a symmetric AES key
	public static SecretKey generateAESKey() throws Exception {
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(256); // You can use 128 or 192 bits as well
		return keyGenerator.generateKey();
	}

	// Encrypt the data using AES
	public static byte[] encryptAES(byte[] data, SecretKey secretKey) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return aesCipher.doFinal(data);
	}

	// Encrypt the AES key using RSA
	public static byte[] encryptRSA(SecretKey secretKey, PublicKey publicKey) throws Exception {
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return rsaCipher.doFinal(secretKey.getEncoded());
	}

	// Decrypt the AES key using RSA
	public static SecretKey decryptRSA(byte[] encryptedKey, PrivateKey privateKey) throws Exception {
		Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] decryptedKey = rsaCipher.doFinal(encryptedKey);
		return new SecretKeySpec(decryptedKey, "AES");
	}

	// Decrypt the data using AES
	public static byte[] decryptAES(byte[] encryptedData, SecretKey secretKey) throws Exception {
		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
		return aesCipher.doFinal(encryptedData);
	}

	public static PublicKey getPrivateKey(String certificatePath) throws Exception {
		// Load the certificate and extract the private key
		try (FileInputStream fis = new FileInputStream(certificatePath)) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(fis);
			return cert.getPublicKey(); // Modify if you have the private key separately
		}
	}

	public String[] fetchCertificates() throws Exception {
		// Fetch XML
		String metadataUrl = "https://access.axiomprotect.com:6653/AxiomProtect/v1/idp/getidpMatadataXML?id=3b1zRT&accountId=8797893D-7F0D-4B5F-9F6E-DE1706BC33D0";
		HttpURLConnection connection = (HttpURLConnection) new URL(metadataUrl).openConnection();
		connection.setRequestMethod("GET");

		try (InputStream inputStream = connection.getInputStream()) {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document doc = builder.parse(inputStream);

			// Extract signing and encryption certificates
			XPathFactory xpathFactory = XPathFactory.newInstance();
			XPath xpath = xpathFactory.newXPath();
			String signingCert = (String) xpath.evaluate("//ds:X509Certificate[@Usage='signing']", doc,
					XPathConstants.STRING);
			String encryptionCert = (String) xpath.evaluate("//ds:X509Certificate[@Usage='encryption']", doc,
					XPathConstants.STRING);

			return new String[] { signingCert, encryptionCert };
		}
	}

	public X509Certificate loadCertificate(String certificateString) throws Exception {
		// Remove the header and footer if present
		String cleanCert = certificateString.replace("-----BEGIN CERTIFICATE-----", "")
				.replace("-----END CERTIFICATE-----", "").replaceAll("\\s+", ""); // Remove whitespace

		// Convert the cleaned certificate string to a byte array
		byte[] certBytes = cleanCert.getBytes();

		// Create a CertificateFactory for X.509 certificates
		CertificateFactory factory = CertificateFactory.getInstance("X.509");

		// Generate the certificate from the byte array
		try (ByteArrayInputStream inputStream = new ByteArrayInputStream(certBytes)) {
			return (X509Certificate) factory.generateCertificate(inputStream);
		}
	}

//	public String createSAMLRedirectRequests() {
//		try {
//			// Construct the AuthnRequest XML
//			String[] fetchCertificates = fetchCertificates();
//			String string = fetchCertificates[0];
//			// Initialize the certificate from the fetched string
//			X509Certificate certificate = loadCertificate(string);
//			StringBuilder samlRequest = new StringBuilder();
//			samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ")
//					.append("ID=\"id-").append(UUID.randomUUID().toString()).append("\" ").append("Version=\"2.0\" ")
//					.append("IssueInstant=\"").append(Instant.now().toString()).append("\" ").append("Destination=\"")
//					.append(idpSsoUrl).append("\" ")
//					.append("AssertionConsumerServiceURL=\"http://103.76.249.54:8082/acs\" ")
//					.append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">")
//					.append("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">").append(spEntityID)
//					.append("</saml:Issuer>").append("<samlp:NameIDPolicy Format=\"").append(nameIdFormat)
//					.append("\" AllowCreate=\"true\"/>").append("</samlp:AuthnRequest>");
//
//			// Parse the XML string into a Document object
//			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//			dbf.setNamespaceAware(true);
//			DocumentBuilder db = dbf.newDocumentBuilder();
//			Document document = db
//					.parse(new ByteArrayInputStream(samlRequest.toString().getBytes(StandardCharsets.UTF_8)));
//
//			// Create an XMLSignatureFactory instance
//			XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
//
//			// Create a reference to what you're signing (the whole document in this case)
//			Reference ref = signatureFactory.newReference("", // Reference the whole document (empty URI)
//					signatureFactory.newDigestMethod(DigestMethod.SHA256, null),
//					Collections.singletonList(
//							signatureFactory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
//					null, null);
//
//			// Create SignedInfo using Canonicalization and Signature methods
//			SignedInfo signedInfo = signatureFactory.newSignedInfo(
//					signatureFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
//							(C14NMethodParameterSpec) null),
//					signatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
//					Collections.singletonList(ref));
//
//			// KeyInfoFactory to include X509 certificate in the signature
//			KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
//			X509Data x509Data = keyInfoFactory.newX509Data(Collections.singletonList(certificate));
//			KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
//
//			// Create the XMLSignature with SignedInfo and KeyInfo
//			javax.xml.crypto.dsig.XMLSignature signature = signatureFactory.newXMLSignature(signedInfo, keyInfo);
//
//			// Create a DOMSignContext with the private key and document to sign
//			DOMSignContext signContext = new DOMSignContext(privateKey, document.getDocumentElement());
//
//			// Sign the document
//			signature.sign(signContext);
//
//			// Convert the signed document back to a string
//			TransformerFactory transformerFactory = TransformerFactory.newInstance();
//			Transformer transformer = transformerFactory.newTransformer();
//			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
//			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
//			ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
//			DOMSource source = new DOMSource(document);
//			StreamResult result = new StreamResult(outputStream);
//			transformer.transform(source, result);
//			String signedSAMLRequest = new String(outputStream.toByteArray(), StandardCharsets.UTF_8);
//
//			// Base64 encode the signed request
//			String encodedRequest = Base64.getEncoder()
//					.encodeToString(signedSAMLRequest.getBytes(StandardCharsets.UTF_8));
//
//			// URL encode the Base64-encoded string
//			return URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());
//
//		} catch (Exception e) {
//			e.printStackTrace();
//			return null;
//		}
//	}

	public void debugAuthnRequest(AuthnRequest authnRequest) {
		System.out.println("AuthnRequest ID: " + authnRequest.getID());
		System.out.println("Issue Instant: " + authnRequest.getIssueInstant());
		System.out.println("Destination: " + authnRequest.getDestination());
		System.out.println("Protocol Binding: " + authnRequest.getProtocolBinding());
		System.out.println("Assertion Consumer Service URL: " + authnRequest.getAssertionConsumerServiceURL());
		System.out.println(
				"Issuer: " + (authnRequest.getIssuer() != null ? authnRequest.getIssuer().getValue() : "null"));
		System.out.println("NameIDPolicy: " + (authnRequest.getNameIDPolicy() != null ? "Set" : "null"));
	}

	// Method to create a SAML object
	public <T> T createSamlObject(Class<T> clazz) {
		try {
			if (clazz.equals(AuthnRequest.class)) {
				return (T) new AuthnRequestBuilder().buildObject();
			} else if (clazz.equals(Issuer.class)) {
				return (T) new IssuerBuilder().buildObject();
			} else if (clazz.equals(NameIDPolicy.class)) {
				return (T) new NameIDPolicyBuilder().buildObject();
			}
			// Add more cases for other SAML types if needed
			throw new IllegalArgumentException("Unsupported SAML class: " + clazz);
		} catch (Exception e) {
			throw new RuntimeException("Error creating SAML object", e);
		}
	}

//	public String createSAMLRedirectRequest() {
//		try {
//			String acsUrl = "http://103.76.249.54:8082/acs";
//			// Build AuthnRequest
//			AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
//			AuthnRequest authnRequest = authnRequestBuilder.buildObject();
//			authnRequest.setID("id-" + UUID.randomUUID().toString()); // Unique ID
//			authnRequest.setVersion(SAMLVersion.VERSION_20); // SAML 2.0
//			authnRequest.setIssueInstant(DateTime.now()); // Current timestamp
//			authnRequest.setDestination(idpSsoUrl); // Destination IdP SSO URL
//			authnRequest.setAssertionConsumerServiceURL(acsUrl); // Assertion Consumer Service URL
//			authnRequest.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI); // HTTP-Redirect Binding
//
//			// Set Issuer (SP entity ID)
//			IssuerBuilder issuerBuilder = new IssuerBuilder();
//			Issuer issuer = issuerBuilder.buildObject();
//			issuer.setValue(spEntityID);
//			authnRequest.setIssuer(issuer);
//
//			// Set NameIDPolicy
//			NameIDPolicyBuilder nameIDPolicyBuilder = new NameIDPolicyBuilder();
//			NameIDPolicy nameIDPolicy = nameIDPolicyBuilder.buildObject();
//			nameIDPolicy.setFormat(nameIdFormat); // Name ID Format (e.g., transient or persistent)
//			nameIDPolicy.setAllowCreate(true); // Allow Name ID creation
//			authnRequest.setNameIDPolicy(nameIDPolicy);
//			
//			Element signAndMarshall = SAMLUtils.signAndMarshall(authnRequest);
////			// **ENCRYPT THE AUTHNREQUEST**
//			String encryptedAuthnRequest = SAMLUtils.encrypt(signAndMarshall); // Use the encryption method created earlier
////
////			// Convert to XML and Base64 encode
////			String samlRequestXML = serialize(encryptedAuthnRequest); // Serialize to XML
//			// Convert to XML, sign if necessary, Base64 encode, then URL encode
////			String samlRequestXML = serialize(authnRequest); // Serialize to XML
//			byte[] encodedBytes = Base64.getEncoder().encode(encryptedAuthnRequest.getBytes());
//			String base64EncodedRequest = new String(encodedBytes, StandardCharsets.UTF_8);
////	        String base64EncodedRequest = Base64.encodeBytes(samlRequestXML.getBytes());
//			return URLEncoder.encode(base64EncodedRequest, "UTF-8");
//		} catch (Exception e) {
//			e.printStackTrace();
//			return null;
//		}
//	}

	public String encodeSAMLRequest(AuthnRequest authnRequest) {
		// Serialize the AuthnRequest to XML
		debugAuthnRequest(authnRequest);
		String xml = null;
		try {
			xml = serialize(authnRequest);
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // Implement serialization logic
		System.out.println("xml :" + xml);
		// Compress if necessary (GZIP)
//		byte[] compressed = compress(xml); // Implement compression logic

		// Base64 encode
//		return Base64.getEncoder().encodeToString(xml);
		String encodedRequest = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));

		// URL encode the Base64-encoded string
		String urlEncodedRequest = null;
		try {
			urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Return the final encoded SAML request
		return urlEncodedRequest;
	}

	private String serialize(AuthnRequest authnRequest) throws MarshallingException {
		try {
			// Get the marshaller factory
//	        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

			// Get the marshaller for the AuthnRequest object
			Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);

			// Marshal the AuthnRequest into a DOM element
			Element element = marshaller.marshall(authnRequest);

			// Convert the DOM element into a string (XML)
			StringWriter writer = new StringWriter();
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.transform(new DOMSource(element), new StreamResult(writer));

			return writer.toString(); // Return the XML string

		} catch (Exception e) {
			e.printStackTrace();
			throw new MarshallingException("Error serializing AuthnRequest", e);
		}
	}

//	public String serialize(AuthnRequest authnRequest) {
//		try {
//			// Build the XML object
//			Element element = authnRequest.getDOM(); // Convert to DOM element
//
//			// Print the DOM Element to System.out
//			TransformerFactory transformerFactory = TransformerFactory.newInstance();
//			Transformer transformer = transformerFactory.newTransformer();
//			DOMSource source = new DOMSource(element);
//			StringWriter writer = new StringWriter();
//			transformer.transform(source, new StreamResult(writer));
//
//			// Output the serialized XML to the console
//			String xmlString = writer.getBuffer().toString();
//			System.out.println("Serialized AuthnRequest XML: " + xmlString);
//
//			return xmlString; // Return the serialized XML
//		} catch (Exception e) {
//			throw new RuntimeException("Error serializing AuthnRequest", e);
//		}
//	}

	public byte[] compress(String data) {
		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
				GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
			gzipOutputStream.write(data.getBytes(StandardCharsets.UTF_8));
			gzipOutputStream.close();
			return byteArrayOutputStream.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("Error compressing data", e);
		}
	}

//	public String createSAMLRequest() {
//	    try {
//	        // Create AuthnRequest manually (without OpenSAML)
//	        StringBuilder samlRequest = new StringBuilder();
//
//	        samlRequest.append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ")
//	                   .append("ID=\"id-").append(UUID.randomUUID().toString()).append("\" ")
//	                   .append("IssueInstant=\"").append(Instant.now().toString()).append("\" ")
//	                   .append("Version=\"2.0\" ")
//	                   .append("Destination=\"").append(idpSsoUrl).append("\" ")
//	                   .append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">");
//
//	        samlRequest.append("<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">")
//	                   .append(spEntityID)
//	                   .append("</saml:Issuer>");
//
//	        samlRequest.append("<samlp:NameIDPolicy Format=\"").append(nameIdFormat).append("\" />");
//
//	        samlRequest.append("</samlp:AuthnRequest>");
//
//	        // Encode the request as Base64 and URL encode it
//	        String encodedRequest = Base64.getEncoder().encodeToString(samlRequest.toString().getBytes(StandardCharsets.UTF_8));
//	        return URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());
//
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	        throw new RuntimeException("Error creating SAML request", e);
//	    }
//	}

	public String createSAMLRequests() {
		try {
			InitializationService.initialize();

			// Create AuthnRequest
			AuthnRequestBuilder authnRequestBuilder = new AuthnRequestBuilder();
			AuthnRequest authnRequest = authnRequestBuilder.buildObject();

			// Set issuer (your SP entityID)
			Issuer issuer = new IssuerBuilder().buildObject();
			issuer.setValue("http://localhost:8082/acs");
			authnRequest.setIssuer(issuer);

			// Set IDP ACS URL
			authnRequest.setDestination(idpSsoUrl);

			// Generate unique ID
			authnRequest.setID("id-" + UUID.randomUUID().toString());

			// Set NameIDPolicy
			NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
			nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
			authnRequest.setNameIDPolicy(nameIDPolicy);
			// Set time constraints
//            DateTime now = DateTime.now();
//            authnRequest.setNotBefore(now);
//            authnRequest.setNotOnOrAfter(now.plusMinutes(5));

//			// Set time constraints
//			DateTime now = new DateTime(); // Creates a new DateTime instance
//			authnRequest.setNotBefore(now);
//			authnRequest.setNotOnOrAfter(now.add(5 * 60 * 1000)); // Adds 5 minutes in milliseconds

			// (Optional) Create signature if required by IdP
			/*
			 * Signature signature = SignatureSupport.buildSignature();
			 * signature.setSigningCredential(getSigningCredential()); // Implement this
			 * method signature.setSignatureAlgorithm(SignatureConstants.
			 * ALGO_ID_SIGNATURE_RSA_SHA256); authnRequest.setSignature(signature);
			 */

			// Set ProtocolBinding (for example, HTTP-POST)
			authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");

			// Set entity endpoint if required (you may need to define this based on your
			// application's needs)
			// Example: set the assertion consumer service URL
			String entityEndpoint = idpSsoUrl; // Replace with your actual endpoint
			authnRequest.setAssertionConsumerServiceURL(entityEndpoint);
			// Serialize and encode
			return serializeAndEncode(authnRequest);
		} catch (Exception e) {
			throw new RuntimeException("Error creating SAML request", e);
		}
	}

	public boolean validateSAMLResponse(Response response) {
		try {
			// Validate signature if needed
			if (response.getSignature() != null) {
				Credential credential = getIDPCredential(); // Implement this method to fetch your IDP's public key
															// credential
				SignatureValidator.validate(response.getSignature(), credential);
			}

			// Check the status of the response
			if (response.getStatus() != null && response.getStatus().getStatusCode().getValue()
					.equals(org.opensaml.saml.saml1.core.StatusCode.SUCCESS)) {
				return true; // Valid response
			} else {
				return false; // Invalid response
			}
		} catch (Exception e) {
			throw new RuntimeException("Error validating SAML response", e);
		}
	}

	public String serializeAndEncode(XMLObject xmlObject) {
		try {
			// Obtain the marshaller factory
			MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();

			// Get the marshaller for the specific XMLObject type
			Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);

			// Marshal the XMLObject to a DOM element
			Element element = marshaller.marshall(xmlObject);

			// Convert to string
			StringWriter stringWriter = new StringWriter();
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			transformer.transform(new DOMSource(element), new StreamResult(stringWriter));

			// Return Base64 encoded string
			return Base64.getEncoder().encodeToString(stringWriter.toString().getBytes(StandardCharsets.UTF_8));
		} catch (Exception e) {
			throw new RuntimeException("Error serializing SAML request", e);
		}
	}

	public String serializeAndEncode(AuthnRequest authnRequest) {
		try {
			// Use the Marshaller to convert to XML
			Marshaller marshaller = XMLObjectSupport.getMarshaller(authnRequest);
			Element element = marshaller.marshall(authnRequest);

			// Convert the Element to a String
			StringWriter stringWriter = new StringWriter();
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.transform(new DOMSource(element), new StreamResult(stringWriter));
			String xmlString = stringWriter.toString();

			// Base64 encode
			return Base64.getEncoder().encodeToString(xmlString.getBytes(StandardCharsets.UTF_8));
		} catch (MarshallingException e) {
			throw new RuntimeException("Error marshalling SAML request", e);
		} catch (Exception e) {
			throw new RuntimeException("Error serializing and encoding SAML request", e);
		}
	}

//	// Implement this method to return your signing credential
//	private Credential getSigningCredential() {
//		// Your implementation here
//		return null; // Placeholder
//	}
//
	// Implement this method to fetch your IDP's public key credential
	private Credential getIDPCredential() {
		// Your implementation here
		return null; // Placeholder
	}

	public Response parseSAMLResponse(String samlResponse) {
		try {
			// Initialize OpenSAML
			InitializationService.initialize();

			// Decode the Base64-encoded SAML response
			byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
			String xmlString = new String(decodedBytes, StandardCharsets.UTF_8);

			// Convert the XML string to a DOM Element
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlString.getBytes(StandardCharsets.UTF_8));
			Element element = builder.parse(inputStream).getDocumentElement();

			// Get the unmarshaller for the Response element
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);

			// Unmarshal the Element to a Response object
			XMLObject xmlObject = unmarshaller.unmarshall(element);

			if (xmlObject instanceof Response) {
				return (Response) xmlObject; // Cast to Response and return
			} else {
				throw new RuntimeException("Unmarshalling failed: XMLObject is not a Response");
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException("Error parsing SAML response: " + e.getMessage(), e);
		}
	}

	public static Map<String, String> decodeSamlResponse(String encodedSamlResponse) {
		Map<String, String> keyMap = new HashMap<>();

		try {
			// Decode the Base64 encoded SAML Response
			byte[] decodedBytes = Base64.getDecoder().decode(encodedSamlResponse);
			String decodedXml = new String(decodedBytes);
//        System.out.println("decoded samlresponse: " + decodedXml);

			// Parse the XML
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document document = builder.parse(new InputSource(new StringReader(decodedXml)));

			// Normalize the XML structure
			document.getDocumentElement().normalize();

			// Extract key points from the XML
			Element responseElement = document.getDocumentElement();

			// Get Response attributes
			keyMap.put("ID", responseElement.getAttribute("ID"));
			keyMap.put("Version", responseElement.getAttribute("Version"));
			keyMap.put("Issue Instant", responseElement.getAttribute("IssueInstant"));
			keyMap.put("Destination", responseElement.getAttribute("Destination"));
			keyMap.put("In Response To", responseElement.getAttribute("InResponseTo"));

			// Get Issuer
			NodeList issuerList = document.getElementsByTagName("saml:Issuer");
			int length = issuerList.getLength();
			if (issuerList.getLength() > 0) {
				keyMap.put("Issuer", issuerList.item(0).getTextContent());
			}

			// Get Status
			NodeList statusList = document.getElementsByTagName("saml:Status");
			if (statusList.getLength() > 0) {
				Element statusElement = (Element) statusList.item(0);
				NodeList statusCodeList = statusElement.getElementsByTagName("saml:StatusCode");
				if (statusCodeList.getLength() > 0) {
					Element statusCodeElement = (Element) statusCodeList.item(0);
					keyMap.put("Status Code", statusCodeElement.getAttribute("Value"));
				}
			}

			// Get Conditions
			NodeList conditionsList = document.getElementsByTagName("saml:Conditions");
			int length1 = conditionsList.getLength();
			if (conditionsList.getLength() > 0) {
				Element conditions = (Element) conditionsList.item(0);
				keyMap.put("Not Before", conditions.getAttribute("NotBefore"));
				keyMap.put("Not On Or After", conditions.getAttribute("NotOnOrAfter"));
			}
			// Get Assertion
			NodeList assertionList = document.getElementsByTagName("saml:Assertion");
			if (assertionList.getLength() > 0) {
				Element assertion = (Element) assertionList.item(0);
				keyMap.put("Assertion ID", assertion.getAttribute("ID"));
				keyMap.put("Assertion Issue Instant", assertion.getAttribute("IssueInstant"));

				// Get Subject
				NodeList subjectList = assertion.getElementsByTagName("saml:Subject");
				if (subjectList.getLength() > 0) {
					Element subject = (Element) subjectList.item(0);
					NodeList nameIdList = subject.getElementsByTagName("saml:NameID");
					if (nameIdList.getLength() > 0) {
						keyMap.put("Name ID", nameIdList.item(0).getTextContent());
					}
				}

				// Get AuthnStatement
				NodeList authnStatementList = assertion.getElementsByTagName("saml:AuthnStatement");
				if (authnStatementList.getLength() > 0) {
					Element authnStatement = (Element) authnStatementList.item(0);
					keyMap.put("Authn Instant", authnStatement.getAttribute("AuthnInstant"));
					keyMap.put("Session Index", authnStatement.getAttribute("SessionIndex"));
				}

				// Get AttributeStatement
				NodeList attributeStatementList = assertion.getElementsByTagName("saml:AttributeStatement");
				if (attributeStatementList.getLength() > 0) {
					Element attributeStatement = (Element) attributeStatementList.item(0);
					NodeList attributes = attributeStatement.getElementsByTagName("saml:Attribute");
					for (int i = 0; i < attributes.getLength(); i++) {
						Element attribute = (Element) attributes.item(i);
						String name = attribute.getAttribute("Name");
						String value = attribute.getElementsByTagName("saml:AttributeValue").item(0).getTextContent();
						keyMap.put(name, value);
					}
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return keyMap;
	}

}
