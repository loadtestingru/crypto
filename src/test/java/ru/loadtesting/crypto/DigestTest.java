package ru.loadtesting.crypto;

import lombok.SneakyThrows;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DigestTest {


    @SneakyThrows
    @Test
    public void gostTest(){
        String data = "HelloWorld";
        String gost256Result = "4dab8cbbf36ca98f49abc4e6b0c0a9eb41cb8bf2691f0a47ae38a08fb67d46d0";
        String gost512Result = "75d9639ed57f6f611303cd8bce254d754bd9dc4dffe9e4c11e1833ecc24c91bd58da855780f105b8ad65db26f212c9e6274c8849384c6dcabdffd2b6b331e07a";
        String sha512Result = "8ae6ae71a75d3fb2e0225deeb004faf95d816a0a58093eb4cb5a3aa0f197050d7a4dc0a2d5c6fbae5fb5b0d536a0a9e6b686369fa57a027687c3630321547596";
        byte[] result;

        //sha512
        result = DigestService.calculateDigest(data.getBytes(),"SHA512");
        assertEquals(sha512Result, Hex.toHexString(result));

        //gost
        result = DigestService.calculateDigest(data.getBytes(),"GOST3411-2012-256");
        assertEquals(gost256Result, Hex.toHexString(result));

        result = DigestService.calculateDigest(data.getBytes(),"GOST3411-2012-512");
        assertEquals(gost512Result, Hex.toHexString(result));

        //gost default
        result = DigestService.calculateGOSTDigest(data.getBytes());
        assertEquals(gost256Result, Hex.toHexString(result));

        MessageDigest digest;

        digest = DigestService.createGOSTDigest();
        for(int i=0;i<data.length();i++){
            DigestService.updateDigest(digest,data.substring(i,i+1).getBytes());
        }
        assertEquals(Hex.toHexString(DigestService.finalizeDigest(digest)),gost256Result);

        digest = DigestService.createDigest("SHA512");
        for(int i=0;i<data.length();i++){
            DigestService.updateDigest(digest,data.substring(i,i+1).getBytes());
        }
        assertEquals(Hex.toHexString(DigestService.finalizeDigest(digest)),sha512Result);

    }
}
