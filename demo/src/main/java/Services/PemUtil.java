package Services;

import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.Reader;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class PemUtil {
	static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        try (Reader reader = new FileReader(filename);
             PEMParser pemParser = new PEMParser(reader)) {
            PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
            return new JcaPEMKeyConverter().getPrivateKey(keyInfo);
        }
    }

    public static X509Certificate loadCertificate(String filename) throws Exception {
        try (Reader reader = new FileReader(filename);
             PEMParser pemParser = new PEMParser(reader)) {
            X509CertificateHolder certificateHolder = (X509CertificateHolder) pemParser.readObject();
            return  convertToX509Certificate(certificateHolder);
        }
    }
    private static X509Certificate convertToX509Certificate(X509CertificateHolder certificateHolder) throws Exception {
        byte[] certificateBytes = certificateHolder.getEncoded();
        try (ByteArrayInputStream bais = new ByteArrayInputStream(certificateBytes)) {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(bais);
        }
    }
}
