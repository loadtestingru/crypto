package ru.loadtesting.crypto;

import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;


public class ContainerService extends CryptoTools{

    /**
     * Read pfx container
     * @param pfx data of pfx container
     * @param password password for decrypt
     * @return {@link Map} of stored certificates and private keys in pfx, key is alias name
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws CertificateException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static Map<String,CertificatePrivateKeyPair> readPfxContainer(byte[] pfx, String password) throws KeyStoreException, NoSuchProviderException, CertificateException, IOException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Map<String,CertificatePrivateKeyPair> result = new HashMap<>();
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(new ByteArrayInputStream(pfx), password.toCharArray());

        Enumeration enumeration = keyStore.aliases();
        while(enumeration.hasMoreElements()){
            String alias = (String) enumeration.nextElement();
            if(keyStore.isCertificateEntry(alias)){
                result.put(alias,new CertificatePrivateKeyPair((X509Certificate)keyStore.getCertificate(alias),null));
            }
            else if(keyStore.isKeyEntry(alias)){
                result.put(alias,new CertificatePrivateKeyPair((X509Certificate)keyStore.getCertificate(alias),(PrivateKey)keyStore.getKey(alias,  password.toCharArray())));
            }
        }
        return result;
    }

    /**
     * Build pfx container for {@link X509Certificate} and {@link PrivateKey}
     * @param aliasName name of pfx stored alias
     * @param certificate certificate to put to pfx
     * @param privateKey  privateKey to put to pfx
     * @param password password of container
     * @return {@link byte[]} representation of pfx
     * @throws Exception
     */
    public static byte[] generatePfxContainer(String aliasName, X509Certificate certificate, PrivateKey privateKey, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12",getProviderName());
        ks.load(null,password.toCharArray());
        ks.setKeyEntry(aliasName, privateKey, password.toCharArray(), new java.security.cert.Certificate[] {certificate});
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ks.store(outputStream,password.toCharArray());
        return outputStream.toByteArray();
    }

}
