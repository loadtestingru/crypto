package ru.loadtesting.crypto;


import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class KeyService extends CryptoTools {


    public static KeyPair generateDefaultECGOST2012KeyPair() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(DEFAULT_GOST_KEYPAIRGENERATOR, getProviderName());
        AlgorithmParameterSpec spec = new GOST3410ParameterSpec(DEFAULT_GOST_CURVE);
        keyPairGenerator.initialize(spec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateECKeyPair(String algorithm,String curve) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(algorithm, getProviderName());
        AlgorithmParameterSpec spec = new ECNamedCurveGenParameterSpec(curve);
        keyPairGenerator.initialize(spec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair generateKeyPair(String algorithm,AlgorithmParameterSpec spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(algorithm, getProviderName());
        keyPairGenerator.initialize(spec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generate PEM string from {@link PrivateKey}
     * @param privateKey privateKey use to create pem
     * @param algorithmOID Algorithm used to encrypt key. <p>If null, then {@link JcaPKCS8Generator#PBE_SHA1_3DES} is used</p>
     * @param password password used for encryption
     * @return String representation of stored private key
     * @throws IOException
     * @throws OperatorCreationException
     */
    public static String generatePrivateKeyPem(PrivateKey privateKey, String algorithmOID, String password) throws IOException, OperatorCreationException {
        OutputEncryptor encryptor;
        if(password==null || password.equals("")){
            encryptor=null;
        }else{
            ASN1ObjectIdentifier identifier;
            if(algorithmOID==null || algorithmOID.equals("")){
                identifier = JcaPKCS8Generator.PBE_SHA1_3DES; //default algorithm
            }else{
                identifier=new ASN1ObjectIdentifier(algorithmOID);
            }
            JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(identifier);
            encryptorBuilder.setRandom(new SecureRandom());
            encryptorBuilder.setPassword(password.toCharArray()); // password
            encryptor = encryptorBuilder.build();
        }
        JcaPKCS8Generator gen1 = new JcaPKCS8Generator(privateKey,encryptor);
        PemObject obj1 = gen1.generate();
        StringWriter sw1 = new StringWriter();
        try (JcaPEMWriter pw = new JcaPEMWriter(sw1)) {
            pw.writeObject(obj1);
        }
        return sw1.toString();
    }

    /**
     * Extract private key from pem file.
     * @param pemKeyBytes pem string as byte array
     * @param password can be null if unencrypted private key
     * @return extracted {@link PrivateKey}
     * @throws Exception
     */
    public static PrivateKey getPrivateKeyFromPem(byte[] pemKeyBytes, String password) throws Exception {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemKeyBytes)));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(getProviderName());
        KeyPair kp;
        if (object instanceof PEMEncryptedKeyPair)
        {
            // Encrypted KeyPair - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            return kp.getPrivate();
        }
        else if(object instanceof PrivateKeyInfo){
            // Unencrypted private key - no password needed
            PrivateKeyInfo privateKeyInfo=(PrivateKeyInfo) object;
            return converter.getPrivateKey(privateKeyInfo);
        }
        else if(object instanceof PKCS8EncryptedPrivateKeyInfo){
            //todo
            //Encrypted privatekey - we will use provided password
            PKCS8EncryptedPrivateKeyInfo encryptedInfo=(PKCS8EncryptedPrivateKeyInfo) object;
            InputDecryptorProvider provider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build( password.toCharArray() );
            final PrivateKeyInfo privateKeyInfo = encryptedInfo.decryptPrivateKeyInfo( provider );
            return converter.getPrivateKey( privateKeyInfo );
        }
        else
        {
            // Unencrypted key pair - no password needed
            PEMKeyPair ukp = (PEMKeyPair) object;
            kp = converter.getKeyPair(ukp);
            return kp.getPrivate();
        }

    }


    public static String generatePublicKeyPem(PublicKey publicKey) throws Exception {
        StringWriter w = new StringWriter();
        PemWriter pw = new PemWriter(w);
        pw.writeObject(new PemObject("PUBLIC KEY",publicKey.getEncoded()));
        pw.close();
        return w.getBuffer().toString();
    }


    public static PublicKey getPublicKeyFromPem(byte[] pemKeyBytes) throws Exception {
        PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemKeyBytes)));
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(getProviderName());
        if(object instanceof SubjectPublicKeyInfo){
            SubjectPublicKeyInfo info=(SubjectPublicKeyInfo) object;
            return converter.getPublicKey(info);
        }else{
            throw new RuntimeException("Is not public key");
        }
    }


}
