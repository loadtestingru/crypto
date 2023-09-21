package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.Test;
import ru.loadtesting.crypto.store.CertificateSignRequestPrivateKeyPair;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CertificateTest {

    @SneakyThrows
    @Test
    public void doCreateCertificate() throws Exception {
        CertificatePrivateKeyPair ca = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
        System.out.println("Root cert: \r\n"+CertificateService.generatePemCertificate(ca.getCertificate()));
        System.out.println("Root private key: \r\n"+KeyService.generatePrivateKeyPem(ca.getPrivateKey(),null,null));
        CertificatePrivateKeyPair user = CertificateService.generateGOSTCertificate(
                "1.2.643.3.131.1.1=123456,CN=TEST2,surname=Ivanov",
                ca.getCertificate(),
                ca.getPrivateKey(),
                CryptoTools.DEFAULT_GOST_SIGNATURE,
                "http://localhost:8080/cert.cer",
                "http://localhost:8080/cert/ocsp",
                "http://localhost:8080/cert.crl",
                15,
                List.of(KeyPurposeId.id_kp_clientAuth),
                365
        );
        System.out.println("User cert: \r\n"+CertificateService.generatePemCertificate(user.getCertificate()));
        System.out.println("User private key: \r\n"+KeyService.generatePrivateKeyPem(user.getPrivateKey(),null,null));
        byte[] data = "HelloWorld".getBytes();

        byte[] cms =  SignService.signData(user.getCertificate(),user.getPrivateKey(),null,data,true);
        assertTrue(SignService.verifySignedData(cms));

        SignService.signData(ca.getCertificate(),ca.getPrivateKey(),null,data,true);
        assertTrue(SignService.verifySignedData(cms));



    }

    @Test
    public void doCreateCertificateWithRequest() throws Exception {
        CertificatePrivateKeyPair ca = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
        System.out.println("Root cert: "+ Base64.getEncoder().encodeToString(ca.getCertificate().getEncoded()));
        CertificateSignRequestPrivateKeyPair userCSR = CertificateService.buildGOSTCertificateSigningRequest("1.2.643.3.131.1.1=123456,CN=TEST2,surname=Ivanov");
        X509Certificate user = CertificateService.signCertificateSigningRequest(
                userCSR.getRequest(),
                ca.getCertificate(),
                ca.getPrivateKey(),
                CryptoTools.DEFAULT_GOST_SIGNATURE,
                "http://localhost:8080/cert.cer",
                "http://localhost:8080/cert/ocsp",
                "http://localhost:8080/cert.crl",
                15,
                List.of(KeyPurposeId.id_kp_clientAuth),
                365
        );
        System.out.println("User cert: "+Base64.getEncoder().encodeToString(user.getEncoded()));
    }

    @Test
    public void revocationListTest() throws Exception {
        CertificatePrivateKeyPair ca = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
        CertificateSignRequestPrivateKeyPair userCSR = CertificateService.buildGOSTCertificateSigningRequest("1.2.643.3.131.1.1=123456,CN=TEST2,surname=Ivanov");
        X509Certificate user = CertificateService.signCertificateSigningRequest(
                userCSR.getRequest(),
                ca.getCertificate(),
                ca.getPrivateKey(),
                CryptoTools.DEFAULT_GOST_SIGNATURE,
                "http://localhost:8080/cert.cer",
                "http://localhost:8080/cert/ocsp",
                "http://localhost:8080/cert.crl",
                15,
                List.of(KeyPurposeId.id_kp_clientAuth),
                365
        );
        X509Certificate user2 = CertificateService.signCertificateSigningRequest(
                userCSR.getRequest(),
                ca.getCertificate(),
                ca.getPrivateKey(),
                CryptoTools.DEFAULT_GOST_SIGNATURE,
                "http://localhost:8080/cert.cer",
                "http://localhost:8080/cert/ocsp",
                "http://localhost:8080/cert.crl",
                15,
                List.of(KeyPurposeId.id_kp_clientAuth),
                365
        );

        X509CRL crl = CertificateService.generateCertificateRevocationList(ca.getCertificate(),ca.getPrivateKey(),null,1,user);

        assertNotNull(crl.getRevokedCertificate(user));
        assertNull(crl.getRevokedCertificate(user2));

        crl = CertificateService.generateCertificateRevocationList(ca.getCertificate(),ca.getPrivateKey(),CryptoTools.DEFAULT_GOST_SIGNATURE,1,user);

        assertNotNull(crl.getRevokedCertificate(user));
        assertNull(crl.getRevokedCertificate(user2));

    }



    @SneakyThrows
    @Test
    public void pemTest(){
        CertificatePrivateKeyPair ca = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
        String pem = CertificateService.generatePemCertificate(ca.getCertificate());
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"));
        if(pem.endsWith("\r\n")) assertTrue(pem.endsWith("-----END CERTIFICATE-----\r\n"));
        else assertTrue(pem.endsWith("-----END CERTIFICATE-----"));
        System.out.println(pem);
        X509Certificate restored = CertificateService.getCertificateFromPem(pem);
        assertEquals(restored,ca.getCertificate());
        restored = CertificateService.getCertificateFromPem(pem.getBytes());
        assertEquals(restored,ca.getCertificate());

        restored = CertificateService.getCertificateFromPem(pem.replace("-----BEGIN CERTIFICATE-----","").replace("-----END CERTIFICATE-----",""));
        assertEquals(restored,ca.getCertificate());
        restored = CertificateService.getCertificateFromPem(pem.getBytes());
        assertEquals(restored,ca.getCertificate());

    }





}
