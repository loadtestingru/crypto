package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class CryptoProPfxTest {

    @SneakyThrows
    @Test
    public void doOpenPfx(){
        String algorithm = "GOST3411WITHECGOST3410-2012-256";
        byte[] pfx_ = Files.readAllBytes(Path.of(URI.create(this.getClass().getResource("/pfx1.pfx").toString())));
        Map<String,CertificatePrivateKeyPair> pairs = ContainerService.readPfxContainer(pfx_, "12345");

        byte[] dataForSigning = "QWERTY".getBytes();
        pairs.forEach((alias,pair)->{
            System.out.println("Alias: "+alias);
            try {
                byte[] signature = SignService.sign(dataForSigning,algorithm, pair.getPrivateKey());
                Assertions.assertTrue(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));
                signature[signature.length-1] = (byte) ((signature[signature.length-1] == 0x00)?0x01:0x00);
                Assertions.assertFalse(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));

                signature = SignService.sign(dataForSigning,null, pair.getPrivateKey());
                Assertions.assertTrue(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));
                signature[signature.length-1] = (byte) ((signature[signature.length-1] == 0x00)?0x01:0x00);
                Assertions.assertFalse(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));

                byte[] cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,dataForSigning,true);
                Assertions.assertTrue(SignService.verifySignedData(cms));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,dataForSigning,false);
                Assertions.assertTrue(SignService.verifySignedData(cms,dataForSigning));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),algorithm,dataForSigning,true);
                Assertions.assertTrue(SignService.verifySignedData(cms));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),algorithm,dataForSigning,false);
                Assertions.assertTrue(SignService.verifySignedData(cms,dataForSigning));

            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        });
    }

    @SneakyThrows
    @Test
    public void doOpenPfx2(){
        String algorithm = "GOST3411WITHECGOST3410-2012-256";
        byte[] pfx_ = Files.readAllBytes(Path.of(URI.create(this.getClass().getResource("/pfx2.pfx").toString())));
        Map<String,CertificatePrivateKeyPair> pairs = ContainerService.readPfxContainer(pfx_, "1234567890");

        byte[] dataForSigning = "QWERTY".getBytes();
        pairs.forEach((alias,pair)->{
            System.out.println("Alias: "+alias);
            try {
                byte[] signature = SignService.sign(dataForSigning,algorithm, pair.getPrivateKey());
                Assertions.assertTrue(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));
                signature[signature.length-1] = (byte) ((signature[signature.length-1] == 0x00)?0x01:0x00);
                Assertions.assertFalse(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));

                signature = SignService.sign(dataForSigning,null, pair.getPrivateKey());
                Assertions.assertTrue(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));
                signature[signature.length-1] = (byte) ((signature[signature.length-1] == 0x00)?0x01:0x00);
                Assertions.assertFalse(SignService.verify(dataForSigning,signature,algorithm,pair.getCertificate().getPublicKey()));

                byte[] cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,dataForSigning,true);
                Assertions.assertTrue(SignService.verifySignedData(cms));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,dataForSigning,false);
                Assertions.assertTrue(SignService.verifySignedData(cms,dataForSigning));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),algorithm,dataForSigning,true);
                Assertions.assertTrue(SignService.verifySignedData(cms));

                cms = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),algorithm,dataForSigning,false);
                Assertions.assertTrue(SignService.verifySignedData(cms,dataForSigning));

            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        });
    }


}
