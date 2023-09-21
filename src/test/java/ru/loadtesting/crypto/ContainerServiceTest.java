package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ContainerServiceTest {

    @SneakyThrows
    @Test
    public void doPfxTest(){
        CertificatePrivateKeyPair p = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
        byte[] pfx = ContainerService.generatePfxContainer("myAlias",p.getCertificate(),p.getPrivateKey(),"123456");
        Map<String, CertificatePrivateKeyPair> p2 = ContainerService.readPfxContainer(pfx, "123456");
        p2.forEach((alias,pair)->{
            System.out.println("doPfxTest alias: "+alias);
            assertEquals(pair.getCertificate().getSerialNumber(),p.getCertificate().getSerialNumber());
            assertEquals(p.getPrivateKey(),pair.getPrivateKey());

        });
    }





}
