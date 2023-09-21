package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;


public class SignServiceTest {

    @SneakyThrows
    @Test
    public void doCmsTest(){
        byte[] pfx_ = Files.readAllBytes(Path.of(URI.create(this.getClass().getResource("/pfx1.pfx").toString())));
        Map<String, CertificatePrivateKeyPair> pairs = ContainerService.readPfxContainer(pfx_, "12345");
        CertificatePrivateKeyPair wrongP = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=qwe", 365);
        byte[] data = "HelloWorld".getBytes();
        pairs.forEach((alias,pair)->{
            assertDoesNotThrow(()->{
                byte[] cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,data,true);
                System.out.println(Base64.getEncoder().encodeToString(cms));
               // Files.write(Path.of(alias),cms, StandardOpenOption.CREATE);
                assertTrue(SignService.verifySignedData(cms));
                assertTrue(SignService.verifySignedData(pair.getCertificate(),cms));
                assertFalse(SignService.verifySignedData(wrongP.getCertificate(),cms));
                //wrong signature test
                for(int i=1;i<=64;i++){
                    if(cms[cms.length-i] != 0x00) {
                        if(cms[cms.length-i] == 0x01) cms[cms.length-i]=0x02;
                        else cms[cms.length-i] = 0x01;
                        assertFalse(SignService.verifySignedData(cms));
                        break;
                    }
                }
            }) ;
        });
    }

    @SneakyThrows
    @Test
    public void doCmsDigestTest() throws IOException, UnrecoverableKeyException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] pfx_ = Files.readAllBytes(Path.of(URI.create(this.getClass().getResource("/pfx1.pfx").toString())));
        Map<String,CertificatePrivateKeyPair> pairs = ContainerService.readPfxContainer(pfx_, "12345");
        CertificatePrivateKeyPair wrongP = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=qwe", 365);
        byte[] data = "HelloWorld".getBytes();
        byte[] digest = DigestService.calculateGOSTDigest(data);
        pairs.forEach((alias,pair)->{
            assertDoesNotThrow(()->{
                byte[] cms = SignService.signDigest(pair.getCertificate(),pair.getPrivateKey(),null,digest);
                System.out.println(Base64.getEncoder().encodeToString(cms));
                assertTrue(SignService.verifySignedData( cms,data));
                assertTrue(SignService.verifySignedData(pair.getCertificate(),cms,data));
                assertFalse(SignService.verifySignedData(wrongP.getCertificate(),cms,data));
                //wrong signature test
                for(int i=1;i<=64;i++){
                    if(cms[cms.length-i] != 0x00) {
                        if(cms[cms.length-i] == 0x01) cms[cms.length-i]=0x02;
                        else cms[cms.length-i] = 0x01;
                        assertFalse(SignService.verifySignedData( cms,data));
                        break;
                    }
                }
            }) ;
        });

    }

}
