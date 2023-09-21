package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.bouncycastle.openssl.PKCS8Generator;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.RSAKeyGenParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

public class KeyServiceTest {

    @SneakyThrows
    @Test
    public void doGenerateKeyPairTest(){
        KeyPair keyPair = KeyService.generateKeyPair("RSA", new RSAKeyGenParameterSpec(2048,
                RSAKeyGenParameterSpec.F4));
        String alg = CryptoTools.getSignatureAlgorithms(keyPair.getPrivate());
        byte[] data = "HelloWorld".getBytes();
        byte[] signature = SignService.sign(data,alg,keyPair.getPrivate());
        assertTrue(SignService.verify(data,signature,alg,keyPair.getPublic()));
        signature = SignService.sign(data,null,keyPair.getPrivate());
        assertTrue(SignService.verify(data,signature,alg,keyPair.getPublic()));
    }


    @SneakyThrows
    @Test
    public void doPemPrivateKeyTest(){

        KeyPair kp = KeyService.generateDefaultECGOST2012KeyPair();
        PrivateKey pk = kp.getPrivate();
        String pem_no_pass = KeyService.generatePrivateKeyPem(pk,null,null);
        assertTrue(pem_no_pass.startsWith("-----BEGIN PRIVATE KEY-----"));
        PrivateKey pk_restored = KeyService.getPrivateKeyFromPem(pem_no_pass.getBytes(),null);
        assertEquals(pk_restored,pk);
        assertThrows(RuntimeException.class,()->{
            KeyService.getPublicKeyFromPem( KeyService.generatePrivateKeyPem(pk,null,null).getBytes());
        });

        pem_no_pass = KeyService.generatePrivateKeyPem(pk,"","");
        assertTrue(pem_no_pass.startsWith("-----BEGIN PRIVATE KEY-----"));
        pk_restored = KeyService.getPrivateKeyFromPem(pem_no_pass.getBytes(),"");
        pem_no_pass = KeyService.generatePrivateKeyPem(pk,"",null);
        assertTrue(pem_no_pass.startsWith("-----BEGIN PRIVATE KEY-----"));
        pk_restored = KeyService.getPrivateKeyFromPem(pem_no_pass.getBytes(),"");
        assertEquals(pk_restored,pk);
        pk_restored = KeyService.getPrivateKeyFromPem(pem_no_pass.getBytes(),"");
        assertEquals(pk_restored,pk);

        pem_no_pass = KeyService.generatePrivateKeyPem(pk,"1.1.1",null);//algorithm can be any, it is not used because of null password
        assertTrue(pem_no_pass.startsWith("-----BEGIN PRIVATE KEY-----"));
        pk_restored = KeyService.getPrivateKeyFromPem(pem_no_pass.getBytes(),null);
        assertEquals(pk_restored,pk);

        String pem_pass = KeyService.generatePrivateKeyPem(pk,null,"12345");
        assertTrue(pem_pass.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        pk_restored = KeyService.getPrivateKeyFromPem(pem_pass.getBytes(),"12345");
        assertEquals(pk_restored,pk);

        String pem_pass2 = KeyService.generatePrivateKeyPem(pk, PKCS8Generator.PBE_SHA1_RC4_128.toString(),"12345");
        assertTrue(pem_pass2.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        pk_restored = KeyService.getPrivateKeyFromPem(pem_pass2.getBytes(),"12345");
        assertEquals(pk_restored,pk);

        PublicKey pub = kp.getPublic();
        String publicPem = KeyService.generatePublicKeyPem(pub);
        System.out.println(publicPem);

        PublicKey pub_restored = KeyService.getPublicKeyFromPem(publicPem.getBytes());

        assertEquals(pub,pub_restored);

    }
}
