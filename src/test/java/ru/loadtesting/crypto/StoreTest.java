package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;
import ru.loadtesting.crypto.store.CertificateSignRequestPrivateKeyPair;

import static org.junit.jupiter.api.Assertions.*;

public class StoreTest {

    @SneakyThrows
    @Test
    public void doStoreTest1(){
        CertificatePrivateKeyPair pair = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 1);
        CertificatePrivateKeyPair pair2 = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 1);

        assertEquals(pair,new CertificatePrivateKeyPair(pair.getCertificate(),pair.getPrivateKey()));
        assertNotEquals(pair,pair2);
        assertEquals(pair.hashCode(), new CertificatePrivateKeyPair(pair.getCertificate(),pair.getPrivateKey()).hashCode());
        assertNotEquals(pair.hashCode(), pair2.hashCode());

    }

    @SneakyThrows
    @Test
    public void doStoreTest2(){
        CertificateSignRequestPrivateKeyPair pair = CertificateService.buildGOSTCertificateSigningRequest("CN=TEST");
        CertificateSignRequestPrivateKeyPair pair2 = CertificateService.buildGOSTCertificateSigningRequest("CN=TEST");

        assertEquals(pair,new CertificateSignRequestPrivateKeyPair(pair.getRequest(),pair.getPrivateKey()));
        assertNotEquals(pair,pair2);
        assertEquals(pair.hashCode(), new CertificateSignRequestPrivateKeyPair(pair.getRequest(),pair.getPrivateKey()).hashCode());
        assertNotEquals(pair.hashCode(), pair2.hashCode());

    }

}
