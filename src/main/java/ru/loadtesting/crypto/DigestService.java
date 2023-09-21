package ru.loadtesting.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class DigestService extends CryptoTools{

    public static byte[] calculateDigest(byte[] message, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance(algorithm,getProviderName());
        return messageDigest.digest(message);
    }

    public static byte[] calculateGOSTDigest(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest messageDigest = MessageDigest.getInstance(DEFAULT_GOST_DIGEST,getProviderName());
        return messageDigest.digest(message);
    }

    public static MessageDigest createDigest(String algorithm) throws Exception {
        return MessageDigest.getInstance(algorithm,getProviderName());
    }

    public static MessageDigest createGOSTDigest() throws Exception {
        return MessageDigest.getInstance(DEFAULT_GOST_DIGEST,getProviderName());
    }



    public static void updateDigest(MessageDigest messageDigest, byte[] message) {
        messageDigest.update(message);
    }

    public static byte[] finalizeDigest(MessageDigest messageDigest) {
        return messageDigest.digest();
    }


}
