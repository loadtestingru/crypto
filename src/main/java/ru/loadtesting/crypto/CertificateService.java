package ru.loadtesting.crypto;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.*;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import ru.loadtesting.crypto.store.CertificatePrivateKeyPair;
import ru.loadtesting.crypto.store.CertificateSignRequestPrivateKeyPair;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Log4j2
public class CertificateService extends CryptoTools{

    private static final JcaX509ExtensionUtils utils;
    static {
        try {
            utils=new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to build JcaX509ExtensionUtils: {}",e.getMessage());
            throw new RuntimeException(e);
        }
    }


    /**
     * Build certificate
     * @param subject subject details. Ordering can be critical for some validation services. Use comma to separate. Example:
     *      * <div><code>
     *      * String subject = "1.2.643.3.131.1.1=0000000000,CN=TEST,surname=Ivanov"
     *      * </code></div>
     *      * See {@link BCStyle}
     * @param caCertificate Signer's certificate
     * @param signatureAlg See {@link DefaultSignatureAlgorithmIdentifierFinder} for possible algorithms names. Can be null - will use default algorithm for private key
     * @param caPrivateKey Signer's private key
     * @param caCertificateUrl url for 1.3.6.1.5.5.7.48.2(authorityInfoAccess.caIssuers) extension: url to caCertificate location
     * @param caOcspUrl url for 1.3.6.1.5.5.7.48.1(authorityInfoAccess.ocsp) extension: url to caCertificate ocsp location
     * @param caCrlUrl url 2.5.29.31(cRLDistributionPoints) extension: url to caCertificate crl list
     * @param keyUsage key usage integer. See {@link KeyUsage}. Example:
     *                 <div><code>
     *                 Integer keyUsage =  X509KeyUsage.nonRepudiation | X509KeyUsage.keyEncipherment | X509KeyUsage.dataEncipherment;
     *                 </code></div>
     * @param extendedKeyUsage see {@link KeyPurposeId}. Example:
     *                 <p><code>
     *                  List<KeyPurposeId> list = List.of(KeyPurposeId.id_kp_clientAuth)
     *                 </code></p>
     * @param days certificate expire days from now
     * @return generate {@link X509Certificate}
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static CertificatePrivateKeyPair generateGOSTCertificate(String subject,
                                                                 X509Certificate caCertificate,
                                                                 PrivateKey caPrivateKey,
                                                                 String signatureAlg,
                                                                 String caCertificateUrl,
                                                                 String caOcspUrl,
                                                                 String caCrlUrl,
                                                                 Integer keyUsage,
                                                                 List<KeyPurposeId> extendedKeyUsage,
                                                                 Integer days) throws Exception {

        CertificateSignRequestPrivateKeyPair signRequestPair = buildGOSTCertificateSigningRequest(subject);
        X509Certificate certificate = signCertificateSigningRequest(signRequestPair.getRequest(),caCertificate,caPrivateKey,signatureAlg,caCertificateUrl,caOcspUrl,caCrlUrl,keyUsage,extendedKeyUsage,days);
        return new CertificatePrivateKeyPair(certificate,signRequestPair.getPrivateKey());
    }


    /**
     * Build signing request and key pair for it
     * @param subject subject details. Ordering can be critical for some validation services. Use comma to separate. Example:
     * <div><code>
     * String subject = "1.2.643.3.131.1.1=0000000000,CN=TEST,surname=Ivanov"
     * </code></div>
     * See {@link BCStyle}
     * @return pair of {@link PKCS10CertificationRequest} and {@link PrivateKey}
     * @throws Exception
     */
    public static CertificateSignRequestPrivateKeyPair buildGOSTCertificateSigningRequest(String subject) throws Exception {
        KeyPair keyPair= KeyService.generateDefaultECGOST2012KeyPair();
        X500Name x500Name = new X500Name(subject);
        PKCS10CertificationRequestBuilder p10Builder =
                new JcaPKCS10CertificationRequestBuilder(
                        x500Name,
                        keyPair.getPublic()
                );
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(DEFAULT_GOST_SIGNATURE);
        return new CertificateSignRequestPrivateKeyPair(p10Builder.build(csBuilder.build(keyPair.getPrivate())),keyPair.getPrivate());
    }

    /**
     * Build certificate based on certificate signing request
     * @param csr certificate signing request
     * @param caCertificate Signer's certificate
     * @param signatureAlg See {@link DefaultSignatureAlgorithmIdentifierFinder} for possible algorithms names. Can be null - will use default algorithm for private key
     * @param caPrivateKey Signer's private key
     * @param caCertificateUrl url for 1.3.6.1.5.5.7.48.2(authorityInfoAccess.caIssuers) extension: url to caCertificate location
     * @param caOcspUrl url for 1.3.6.1.5.5.7.48.1(authorityInfoAccess.ocsp) extension: url to caCertificate ocsp location
     * @param caCrlUrl url 2.5.29.31(cRLDistributionPoints) extension: url to caCertificate crl list
     * @param keyUsage key usage integer. See {@link KeyUsage}. Example:
     *                 <div><code>
     *                 Integer keyUsage =  X509KeyUsage.nonRepudiation | X509KeyUsage.keyEncipherment | X509KeyUsage.dataEncipherment;
     *                 </code></div>
     * @param extendedKeyUsage see {@link KeyPurposeId}. Example:
     *                 <p><code>
     *                  List<KeyPurposeId> list = List.of(KeyPurposeId.id_kp_clientAuth)
     *                 </code></p>
     * @param days certificate expire days from now
     * @return generate {@link X509Certificate}
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws InvalidKeyException
     */
    public static X509Certificate signCertificateSigningRequest(PKCS10CertificationRequest csr,
                                                                X509Certificate caCertificate,
                                                                PrivateKey caPrivateKey,
                                                                String signatureAlg,
                                                                String caCertificateUrl,
                                                                String caOcspUrl,
                                                                String caCrlUrl,
                                                                Integer keyUsage,
                                                                List<KeyPurposeId> extendedKeyUsage,
                                                                Integer days) throws CertIOException, OperatorCreationException, CertificateException, InvalidKeyException {
        signatureAlg = signatureAlg!=null?signatureAlg:getSignatureAlgorithms(caPrivateKey);

        X500Name issuerName = new X500Name(caCertificate.getSubjectX500Principal().getName());
        X500Name subjectName = csr.getSubject();

        Date startDate = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.DAY_OF_YEAR,days);
        Date endDate = calendar.getTime();

        BigInteger serial = new BigInteger(256,new SecureRandom());
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuerName, serial, startDate, endDate, subjectName, csr.getSubjectPublicKeyInfo());

        ASN1EncodableVector purposes = new ASN1EncodableVector();
        if(extendedKeyUsage!=null){
            extendedKeyUsage.forEach(purposes::add);
        }
        GeneralName generalname = new GeneralName(GeneralName.uniformResourceIdentifier,caCrlUrl );
        AuthorityInformationAccess aia = new AuthorityInformationAccess(
                new AccessDescription[]{
                        new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, caCertificateUrl)),
                        new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, caOcspUrl))
                }
        );

        //add extentions
        certBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(keyUsage));
        certBuilder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,utils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
        certBuilder.addExtension(Extension.authorityKeyIdentifier,false,utils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));
        certBuilder.addExtension(Extension.cRLDistributionPoints,false,new CRLDistPoint(new DistributionPoint[]{new DistributionPoint(new DistributionPointName(new GeneralNames(generalname)),null,null)}));
        //certBuilder.addExtension(Extension.certificatePolicies,false,new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32.0")))); ANY_POLICY
        certBuilder.addExtension(Extension.authorityInfoAccess,false, aia);

        return new JcaX509CertificateConverter().
                setProvider(getProviderName())
                .getCertificate(certBuilder.build(new JcaContentSignerBuilder(signatureAlg).build(caPrivateKey)));
    }

    /**
     * Generate GOST self-signed certificate
     * @param subject organization details. Ordering can be critical for some validation services. Use comma to separate. Example:
     *      * <div><code>
     *      * String subject = "CN=TEST_ORG,ou=TEST,surname=Ivanov"
     *      * </code></div>
     * See {@link BCStyle}
     * @param day expire days from now
     * @return Pair of {@link X509Certificate} and {@link PrivateKey}
     * @throws Exception
     */
    public static CertificatePrivateKeyPair generateDefaultGOSTSelfSignedCertificate(String subject, Integer day) throws Exception{
        KeyPair keyPair = KeyService.generateDefaultECGOST2012KeyPair();
        X500Name x500name = new X500Name(subject);
        BigInteger serial = new BigInteger(256,new SecureRandom());
        Date startDate = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.DAY_OF_YEAR,day);
        Date endDate = calendar.getTime();

        ContentSigner contentSigner = new JcaContentSignerBuilder(DEFAULT_GOST_SIGNATURE).build(keyPair.getPrivate());
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(x500name, serial, startDate, endDate, x500name, keyPair.getPublic());

        //add extentions
        certBuilder.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.digitalSignature | X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.basicConstraints,true,new BasicConstraints(true));
        certBuilder.addExtension(Extension.subjectKeyIdentifier,false,utils.createSubjectKeyIdentifier(keyPair.getPublic()));
        certBuilder.addExtension(Extension.certificatePolicies,false,new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier("2.5.29.32.0"))));
        X509CertificateHolder holder =certBuilder.build(contentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(getProviderName()).getCertificate(holder);
        return new CertificatePrivateKeyPair(cert,keyPair.getPrivate());

    }


    /**
     * Build certificate revocation list
     * @param caCertificate Root {@link X509Certificate}
     * @param caPrivateKey Root {@link PrivateKey}
     * @param signatureAlg See {@link DefaultSignatureAlgorithmIdentifierFinder} for possible algorithms names. Can be null - will use default algorithm for private key
     * @param days list duration in days
     * @param revoked list of revoked certificates
     * @return created {@link X509CRL}. Reason is always {@link CRLReason#keyCompromise}
     * @throws Exception
     */
    public static X509CRL generateCertificateRevocationList(X509Certificate caCertificate, PrivateKey caPrivateKey, String signatureAlg, Integer days, X509Certificate... revoked) throws Exception {

        signatureAlg = signatureAlg!=null?signatureAlg:getSignatureAlgorithms(caPrivateKey);

        Date startDate = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.DAY_OF_YEAR,days);
        Date endDate = calendar.getTime();

        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                new X500Name(caCertificate.getSubjectDN().getName()),
                startDate
        );

        builder.setNextUpdate(endDate);
        for (X509Certificate certificate : revoked) {
            builder.addCRLEntry(certificate.getSerialNumber(), new Date(), CRLReason.keyCompromise);
        }

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(signatureAlg);
        contentSignerBuilder.setProvider(getProviderName());
        X509CRLHolder crlHolder = builder.build(contentSignerBuilder.build(caPrivateKey));
        JcaX509CRLConverter converter = new JcaX509CRLConverter();
        converter.setProvider(getProviderName());
        return converter.getCRL(crlHolder);
    }

    /**
     * Get {@link X509Certificate} from pem bytes
     * @param pemCertBytes certificate pem string as byte array
     * @return deserialized {@link X509Certificate}
     * @throws Exception
     */
    public static X509Certificate getCertificateFromPem(byte[] pemCertBytes) throws Exception {
        InputStream stream = new ByteArrayInputStream(pemCertBytes);
        CertificateFactory fact = CertificateFactory.getInstance("X.509",getProviderName());
        return (X509Certificate) fact.generateCertificate(stream);
    }

    /**
     * Get {@link X509Certificate} from pem string
     * @param pemCertificate certificate pem string
     * @return deserialized {@link X509Certificate}
     * @throws Exception
     */
    public static X509Certificate getCertificateFromPem(String pemCertificate) throws Exception {
        if(!pemCertificate.startsWith("-----")) {
            pemCertificate="-----BEGIN CERTIFICATE-----\n"+pemCertificate+"\n-----END CERTIFICATE-----";
        }
        return getCertificateFromPem(pemCertificate.getBytes());
    }

    /**
     *
     * @param certificate certificate used for pem building
     * @return String pem certificate
     * @throws CertificateEncodingException if certificate can not be encoded
     * @throws IOException
     */
    public static String generatePemCertificate(X509Certificate certificate) throws CertificateEncodingException, IOException {
        StringWriter w = new StringWriter();
        PemWriter pw = new PemWriter(w);
        pw.writeObject(new PemObject("CERTIFICATE",certificate.getEncoded()));
        pw.close();
        return w.getBuffer().toString();
    }

}
