package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoToolsTest {
    static final byte[] data = "HelloWorld".getBytes();

    @SneakyThrows
    @Test
    public void getRSASignatureTest(){
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA",CryptoTools.getProviderName());
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        String signatureAlgorithm = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
        Signature signature = Signature.getInstance(signatureAlgorithm,CryptoTools.getProviderName());
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        byte[] sign = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        assertTrue(signature.verify(sign));
    }


    @SneakyThrows
    @Test
    public void getECSignatureTest(){
        List<String> algorithms = List.of("EC","ECDSA");
        List<String> ecCurveNames = List.of(
                "prime192v1","prime192v2","prime192v3",
                "prime239v1","prime239v2","prime239v3",
                "prime256v1","c2pnb163v1","c2pnb163v2",
                "c2pnb163v3","c2pnb176w1","c2tnb191v1",
                "c2tnb191v2","c2tnb191v3","c2pnb208w1",
                "c2tnb239v1","c2tnb239v2","c2tnb239v3",
                "c2pnb272w1","c2pnb304w1","c2tnb359v1",
                "c2pnb368w1","c2tnb431r1"
        );
        algorithms.forEach(alg->{
            ecCurveNames.forEach(curve->{
                assertDoesNotThrow(()->{
                    KeyPair keyPair = KeyService.generateECKeyPair(alg,curve);
                    String signatureAlgorithm = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
                   // System.out.println(alg+"/"+curve+": "+signatureAlgorithm);
                    Signature signature = Signature.getInstance(signatureAlgorithm,CryptoTools.getProviderName());
                    signature.initSign(keyPair.getPrivate());
                    signature.update(data);
                    byte[] sign = signature.sign();
                    signature.initVerify(keyPair.getPublic());
                    signature.update(data);
                    assertTrue(signature.verify(sign));
                });
            });

        });


    }

    @SneakyThrows
    @Test
    public void getGostDefaultSignatureTest(){
        KeyPair keyPair = KeyService.generateDefaultECGOST2012KeyPair();
        String signatureAlgorithm = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
        assertEquals(signatureAlgorithm,"GOST3411WITHECGOST3410-2012-256");
        Signature signature = Signature.getInstance(signatureAlgorithm,CryptoTools.getProviderName());
        signature.initSign(keyPair.getPrivate());
        signature.update(data);
        byte[] sign = signature.sign();
        signature.initVerify(keyPair.getPublic());
        signature.update(data);
        assertTrue(signature.verify(sign));
    }

    @Test
    public void getGost2001SignatureTest(){
        List<String> curveNames = List.of(
                "GostR3410-2001-CryptoPro-A","GostR3410-2001-CryptoPro-B","GostR3410-2001-CryptoPro-C",
                "GostR3410-2001-CryptoPro-XchA","GostR3410-2001-CryptoPro-XchB");
        curveNames.forEach(curve->{
            assertDoesNotThrow(()->{
                KeyPair keyPair = KeyService.generateECKeyPair("ECGOST3410",curve);
                String signatureAlgorithm = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
                assertEquals(signatureAlgorithm,"GOST3411WITHECGOST3410");
                Signature signature = Signature.getInstance(signatureAlgorithm,CryptoTools.getProviderName());
                signature.initSign(keyPair.getPrivate());
                signature.update(data);
                byte[] sign = signature.sign();
                signature.initVerify(keyPair.getPublic());
                signature.update(data);
                assertTrue(signature.verify(sign));
            });
        });
    }

    @Test
    public void getGost512SignatureTest(){
        List<String> curveNames = List.of("Tc26-Gost-3410-12-512-paramSetA","Tc26-Gost-3410-12-512-paramSetB","Tc26-Gost-3410-12-512-paramSetC");
        curveNames.forEach(curve->{
            assertDoesNotThrow(()->{
                KeyPair keyPair = KeyService.generateECKeyPair("ECGOST3410-2012",curve);
                String signatureAlgorithm = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
                assertEquals(signatureAlgorithm,"GOST3411WITHECGOST3410-2012-512");
                Signature signature = Signature.getInstance(signatureAlgorithm,CryptoTools.getProviderName());
                signature.initSign(keyPair.getPrivate());
                signature.update(data);
                byte[] sign = signature.sign();
                signature.initVerify(keyPair.getPublic());
                signature.update(data);
                assertTrue(signature.verify(sign));
            });
        });
    }




}

