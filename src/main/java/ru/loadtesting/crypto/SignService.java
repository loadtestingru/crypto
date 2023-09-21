package ru.loadtesting.crypto;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificate;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;

public class SignService extends CryptoTools{

    /**
     * Generate digital signature for provided data
     * @param signerCertificate certificate used for signature
     * @param signerPrivateKey private key used for signature
     * @param signatureAlgorithm can be null, will use default algorithm for provided private key
     * @param data to sign
     * @param isAttached if <b>true</b> data will be added to result cms file
     * @return CMS byte[] structure. Can be saved as *.sig file or convert to Base64 data
     * @throws CertificateEncodingException
     * @throws IOException
     * @throws CMSException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] signData(X509Certificate signerCertificate, PrivateKey signerPrivateKey, String signatureAlgorithm, byte[] data, Boolean isAttached) throws CertificateEncodingException, IOException, CMSException, InvalidKeyException, OperatorCreationException, NoSuchAlgorithmException {
        signatureAlgorithm = signatureAlgorithm==null?getSignatureAlgorithms(signerPrivateKey):signatureAlgorithm;
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(getProviderName()).build(signerPrivateKey);
        X509CertificateHolder x509CertificateHolder=new X509CertificateHolder(signerCertificate.getEncoded());

        //info builder
        SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        signedAttributes.add(buildSigningCertificateV2Attribute(x509CertificateHolder, contentSigner.getAlgorithmIdentifier()));
        signerInfoBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttributes)));

        //generator
        CMSSignedDataGenerator generator= new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner,x509CertificateHolder));
        generator.addCertificates(new JcaCertStore(List.of(x509CertificateHolder)));
        return generator.generate(new CMSProcessableByteArray(data),isAttached).getEncoded();
    }

    /**
     * Generate digital signature for provided digest
     * @param signerCertificate certificate used for signature
     * @param signerPrivateKey private key used for signature
     * @param signatureAlgorithm can be null, will use default algorithm for provided private key
     * @param digest to sign
     * @return CMS byte[] structure in detached mode. Can be saved as *.sig file or convert to Base64 data
     * @throws CertificateEncodingException
     * @throws IOException
     * @throws CMSException
     * @throws InvalidKeyException
     * @throws OperatorCreationException
     * @throws NoSuchAlgorithmException
     */
    public static byte[] signDigest(X509Certificate signerCertificate, PrivateKey signerPrivateKey, String signatureAlgorithm, byte[] digest) throws CertificateEncodingException, IOException, CMSException, InvalidKeyException, OperatorCreationException, NoSuchAlgorithmException{
        signatureAlgorithm = signatureAlgorithm==null?getSignatureAlgorithms(signerPrivateKey):signatureAlgorithm;
        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(getProviderName()).build(signerPrivateKey);
        X509CertificateHolder x509CertificateHolder=new X509CertificateHolder(signerCertificate.getEncoded());

        //info builder
        ASN1EncodableVector signedAttributes = new ASN1EncodableVector();
        signedAttributes.add(buildSigningCertificateV2Attribute(x509CertificateHolder, contentSigner.getAlgorithmIdentifier()));
        signedAttributes.add(new Attribute(CMSAttributes.messageDigest, new DERSet(new DEROctetString(digest))));
        SignerInfoGeneratorBuilder signerInfoBuilder = new SignerInfoGeneratorBuilder(new BcDigestCalculatorProvider());
        signerInfoBuilder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(signedAttributes)));

        //generator
        CMSSignedDataGenerator generator= new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerInfoBuilder.build(contentSigner,x509CertificateHolder));
        generator.addCertificates(new JcaCertStore(List.of(x509CertificateHolder)));
        return generator.generate(new CMSAbsentContent(),false).getEncoded();
    }

    public static boolean verifySignedData(byte[] cmsData,byte[] data) throws Throwable {
        CMSSignedData cmsSignedData = new CMSSignedData(cmsData);
        if(cmsSignedData.getSignedContent()==null){
            if(data!=null){
                cmsSignedData =new CMSSignedData(new CMSProcessableByteArray(data), cmsData);
            }
        }
        return verifySignedData(cmsSignedData);
    }

    public static boolean verifySignedData(byte[] cmsData) throws Throwable {
        CMSSignedData cmsSignedData = new CMSSignedData(cmsData);
        return verifySignedData(cmsSignedData);
    }

    public static boolean verifySignedData(X509Certificate certificate,byte[] cmsData) throws Throwable {
        CMSSignedData cmsSignedData = new CMSSignedData(cmsData);
        return verifySignedData(certificate,cmsSignedData);
    }

    public static boolean verifySignedData(X509Certificate certificate,byte[] cmsData,byte[] data) throws Throwable {
        CMSSignedData cmsSignedData = new CMSSignedData(cmsData);
        if(cmsSignedData.getSignedContent()==null){
            if(data!=null){
                cmsSignedData =new CMSSignedData(new CMSProcessableByteArray(data), cmsData);
            }
        }
        return verifySignedData(certificate,cmsSignedData);
    }

    public static boolean verifySignedData(CMSSignedData cmsSignedData) {
        Store<X509CertificateHolder> certificatesChain = cmsSignedData.getCertificates();
        for (SignerInformation signer : cmsSignedData.getSignerInfos().getSigners()) {
            SignerId selector = new SignerId(signer.getSID().getIssuer(), signer.getSID().getSerialNumber(), signer.getSID().getSubjectKeyIdentifier());
            @SuppressWarnings("unchecked")
            X509CertificateHolder certificate = (X509CertificateHolder) certificatesChain.getMatches(selector).stream().findFirst().orElseThrow();
            try {
                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
                if (!signer.verify(verifier)) return false;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return true;
    }

    public static boolean verifySignedData(X509Certificate cert,CMSSignedData cmsSignedData) throws CertificateEncodingException, IOException {
        X509CertificateHolder x509CertificateHolder=new X509CertificateHolder(cert.getEncoded());
        Store<X509CertificateHolder> certificatesChain = cmsSignedData.getCertificates();
        for (SignerInformation signer : cmsSignedData.getSignerInfos().getSigners()) {
            SignerId selector = new SignerId(signer.getSID().getIssuer(), signer.getSID().getSerialNumber(), signer.getSID().getSubjectKeyIdentifier());
            @SuppressWarnings("unchecked")
            X509CertificateHolder certificate = (X509CertificateHolder) certificatesChain
                    .getMatches(selector)
                    .stream()
                    .findFirst()
                    .orElseThrow();
            if (!certificate.getSubjectPublicKeyInfo().equals(x509CertificateHolder.getSubjectPublicKeyInfo())
                    || !certificate.getSerialNumber().equals(x509CertificateHolder.getSerialNumber())
                    || !certificate.getSubject().equals(x509CertificateHolder.getSubject())
            ) {
                return false;
            }
            try {
                SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certificate);
                if (!signer.verify(verifier)) return false;
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        return true;

    }


    private static ASN1Encodable buildSigningCertificateV2Attribute(X509CertificateHolder signingCertificateHolder, AlgorithmIdentifier signatureOid) throws IOException, NoSuchAlgorithmException {
        AlgorithmIdentifier digestOid = digestAlgorithmIdentifierFinder.find(signatureOid);
        MessageDigest dig = MessageDigest.getInstance(digestOid.getAlgorithm().getId());
        byte[] certHash = dig.digest(signingCertificateHolder.getEncoded());
        if (digestOid.getAlgorithm().equals(X509ObjectIdentifiers.id_SHA1)) {
            SigningCertificate sc = new SigningCertificate(new ESSCertID(certHash));
            return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificate, new DERSet(sc));
        } else {
            ESSCertIDv2 essCert = new ESSCertIDv2(digestOid, certHash,new IssuerSerial(signingCertificateHolder.getIssuer(),signingCertificateHolder.getSerialNumber()));
            SigningCertificateV2 scv2 = new SigningCertificateV2(new ESSCertIDv2[] { essCert });
            return new Attribute(PKCSObjectIdentifiers.id_aa_signingCertificateV2, new DERSet(scv2));
        }
    }


    /**
     * Calculate signature
     * @param data data for signing
     * @param algorithm See {@link DefaultSignatureAlgorithmIdentifierFinder} for possible algorithms names
     * @param privateKey private key used for signing
     * @return signature
     */
    public static byte[] sign(byte[] data, String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        algorithm = algorithm!=null?algorithm:getSignatureAlgorithms(privateKey);
        Signature signature = Signature.getInstance(algorithm,getProviderName());
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verify signature
     * @param data data that was signed
     * @param signature signature of data
     * @param algorithm See {@link DefaultSignatureAlgorithmIdentifierFinder} for possible algorithms names
     * @param publicKey public key to check signature
     * @return <b>true</b> if signature is correct for provided publicKey
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static boolean verify(byte[] data, byte[] signature,String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance(algorithm,getProviderName());
        signer.initVerify(publicKey);
        signer.update(data);
        return signer.verify(signature);
    }



}
