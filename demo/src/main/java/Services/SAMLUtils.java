package Services;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;

@Service
public class SAMLUtils {
//	private String signingPrivateKeyPath = "C:/Projects/sampleSaml/signpriv.pem"; // Update path
//	private String signingCertPath = "C:/Projects/sampleSaml/signcert.pem"; // Update path
//	private String encryptionPrivateKeyPath = "C:/Projects/sampleSaml/encryptKey.pem"; // Update path
//	private String encryptionCertPath = "C:/Projects/sampleSaml/encryptionCert.pem"; // Update path

	@Value("${saml.sp.entityId}")
	private String spEntityID;

	@Value("${saml.idp.sso.url}")
	private String idpSsoUrl;

	@Value("${saml.nameid.format}")
	private String nameIdFormat;
	
	@Value("${saml.idp.sign.cert.path}")
	private String signingCertPath;

	@Value("${saml.idp.sign.privte.key.path}")
	private String signingPrivateKeyPath;

//	public static String redirect() {
//		// Service Provider metadata
//		ServiceProviderMetadata spMetadata = new ServiceProviderMetadata("http://localhost:8082/sp/metadeta",
////            "http://103.76.249.54:8082/acs", 
//				"http://localhost:8082/acs", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", false);
//
//		PrivateKey privateKey = null;
//		try {
//			privateKey = PemUtil.loadPrivateKey("C:/Projects/sampleSaml/signpriv.pem");
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		// Identity Provider metadata
//		IdentityProvider idp = new IdentityProvider("STG3gJ", "http://localhost:4000/idp/login/STG3gJ",
//				"http://localhost:4000/idp/login/STG3gJ", privateKey);
//
//		// Create the Service Provider
//		ServiceProvider sp = new ServiceProvider(spMetadata);
//
//		// Generate SAML login request (HTTP-Redirect binding)
//		try {
//			BindingContext context = sp.createLoginRequest(idp, "HTTP-Redirect", null);
//			String content = context.getContent();
//			System.out.println(content);
//			String replace = content.replace("http://localhost:4000/idp/login/STG3gJ?SAMLRequest=", "");
//			return replace;
//		} catch (Exception e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		return null;
//	}

	// Build the Signature object for signing the request
	public Signature buildSignature() {
		try {
//			String signingPrivateKeyPath = "C:/Projects/sampleSaml/signpriv.pem"; // Update path
//			String signingCertPath = "C:/Projects/sampleSaml/signcert.pem"; // Update path
			// Load the signing private key and certificate
			PrivateKey privateKey = PemUtil.loadPrivateKey(signingPrivateKeyPath);
			X509Certificate certificate = PemUtil.loadCertificate(signingCertPath);

			BasicCredential signingCredential = new BasicCredential(certificate.getPublicKey(), privateKey);

			SignatureBuilder signatureBuilder = new SignatureBuilder();
			Signature signature = signatureBuilder.buildObject();

			// Set the signing credential and algorithms
			signature.setSigningCredential(signingCredential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			return signature;
		} catch (Exception e) {
			e.printStackTrace(); // Log the error
			return null; // Handle error gracefully
		}
	}

	// Encrypt the AuthnRequest using the encryption PEM
	public static String encrypt(Element authnRequestElement) {
		try {
			String encryptionPrivateKeyPath = "C:/Projects/sampleSaml/encryptKey.pem"; // Update path
			String encryptionCertPath = "C:/Projects/sampleSaml/encryptionCert.pem"; // Update path
			// Load the encryption private key and certificate
			PrivateKey encryptionPrivateKey = PemUtil.loadPrivateKey(encryptionPrivateKeyPath);
			X509Certificate encryptionCertificate = PemUtil.loadCertificate(encryptionCertPath);
			BasicCredential encryptionCredential = new BasicCredential(encryptionCertificate.getPublicKey(),
					encryptionPrivateKey);
			// Configure data encryption parameters
			DataEncryptionParameters dataEncryptionParams = new DataEncryptionParameters();
			dataEncryptionParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);

			// Configure key encryption parameters
			KeyEncryptionParameters keyEncryptionParams = new KeyEncryptionParameters();
			keyEncryptionParams.setEncryptionCredential(encryptionCredential);
			keyEncryptionParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

			// Create the Encrypter object
			Encrypter encrypter = new Encrypter(dataEncryptionParams, keyEncryptionParams);

			// Convert Element to XMLObject
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(authnRequestElement);
			XMLObject authnRequestXMLObject = unmarshaller.unmarshall(authnRequestElement);

			// Now use the XMLObject for encryption
			// Encrypt the AuthnRequest
			EncryptedData encryptedData = encrypter.encryptElement(authnRequestXMLObject, dataEncryptionParams);
			// Encrypt the AuthnRequest element

			// Serialize the EncryptedData to XML string
			Element encryptedElement = XMLObjectProviderRegistrySupport.getMarshallerFactory()
					.getMarshaller(encryptedData).marshall(encryptedData);
			return serialize(encryptedElement); // Return the serialized encrypted element
		} catch (Exception e) {
			e.printStackTrace(); // Log the error
			return null; // Handle error gracefully
		}
	}

//	public static Element signAndMarshall(AuthnRequest authnRequest) {
//	    try {
//	        // Marshall the AuthnRequest to an XML Element
//	        MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
//	        Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);
//	        Element authnRequestElement = marshaller.marshall(authnRequest);
//
//	        // Build and attach the Signature
//	        Signature signature = buildSignature();
//	        authnRequest.setSignature(signature);
//
//	        // Perform signing
//	        SignatureSigningParameters signingParameters = new SignatureSigningParameters();
//	        signingParameters.setSigningCredential(getSigningCredential());
//	        signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
//	        signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
//
//	        SignatureSupport.signObject(authnRequest);
//
//	        // Remarshall after signing
//	        authnRequestElement = marshaller.marshall(authnRequest);
//	        return authnRequestElement;
//	    } catch (Exception e) {
//	        e.printStackTrace();
//	        return null;
//	    }
//	}
	public Element signAndMarshall(AuthnRequest authnRequest) {
		try {
			// Ensure authnRequest is not null and print its state
			if (authnRequest == null) {
				System.out.println("AuthnRequest is null!");
				return null;
			} else {
				System.out.println("AuthnRequest before signing: " + authnRequest.toString());
				// Print relevant properties
				System.out.println("ID: " + authnRequest.getID());
				System.out.println("IssueInstant: " + authnRequest.getIssueInstant());
				System.out.println("Version: " + authnRequest.getVersion());
				// Add more fields as needed
			}

			// Marshall the AuthnRequest to an XML Element
			MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);

			// Check if marshaller is null
			if (marshaller == null) {
				System.out.println("Marshaller is null for AuthnRequest!");
				return null;
			}

			Element authnRequestElement = marshaller.marshall(authnRequest);

			if (authnRequestElement == null) {
				System.out.println("authnRequestElement is null after marshalling!");
			} else {
				System.out.println("AuthnRequestElement created successfully.");
			}

			// Debug output of the marshalled XML
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(authnRequestElement), new StreamResult(writer));
			String xmlString = writer.getBuffer().toString();
			System.out.println("Marshalled AuthnRequest XML: " + xmlString);

			// Build and attach the Signature
			Signature signature = buildSignature();
			if (signature == null) {
				System.out.println("Signature is null!");
				return null;
			}
			authnRequest.setSignature(signature);

			// Prepare signing parameters
			SignatureSigningParameters signingParameters = new SignatureSigningParameters();
			signingParameters.setSigningCredential(getSigningCredential());
			signingParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			signingParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

			// Sign the AuthnRequest
			SignatureSupport.prepareSignatureParams(signature, signingParameters);
			SignatureSupport.signObject(authnRequest, signingParameters);

			// Remarshall after signing
			authnRequestElement = marshaller.marshall(authnRequest);
			return authnRequestElement;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	public static BasicCredential getSigningCredential() {
		try {
			String signingPrivateKeyPath = "C:/Projects/sampleSaml/signpriv.pem"; // Update path
			String signingCertPath = "C:/Projects/sampleSaml/signcert.pem"; // Update path
			// Load the signing private key from PEM file
			PrivateKey signingPrivateKey = PemUtil.loadPrivateKey(signingPrivateKeyPath); // Your method for loading the
																							// private key

			// Load the signing certificate from PEM file
			X509Certificate signingCertificate = PemUtil.loadCertificate(signingCertPath); // Your method for loading
																							// the certificate

			// Create and return a BasicCredential object for signing
			return new BasicCredential(signingCertificate.getPublicKey(), signingPrivateKey);
		} catch (Exception e) {
			e.printStackTrace(); // Handle exceptions properly
			return null; // Handle error gracefully
		}
	}

	// Placeholder for serialization method (to be implemented)
	// Serialize XML Element to String
	private static String serialize(Element element) {
		try {
			TransformerFactory transformerFactory = TransformerFactory.newInstance();
			Transformer transformer = transformerFactory.newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(element), new StreamResult(writer));
			return writer.toString();
		} catch (Exception e) {
			e.printStackTrace(); // Handle error appropriately
			return null; // Return null on error
		}
	}
}
