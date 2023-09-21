
# Crypto Lib for testing
Library for crypto operations testing mostly for GOST standarts.
It is based on BouncyCastle library
Library supports reading private key from CryptoPro pfx with PBE 1.2.840.113549.1.12.1.80, but now only for GOST R 34.10-2012 256 bit key. 

![](https://img.shields.io/badge/java-11-green)

> [!IMPORTANT] 
> It is only for testing, not production ready.

## Usage/Examples

### Build self signed certificate and crl
- Signature is:
    - 1.2.643.7.1.1.3.2
    - id-tc26-signwithdigest-gost3410-12-256
    - алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256 с хэшированием ГОСТ Р 34.11-2012
- GOST EC Key curve is:
    - 1.2.643.7.1.2.1.1.1
    - id-tc26-gost-3410-12-256-paramSetA
    - рабочие параметры А алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256
```java
CertificatePrivateKeyPair ca = CertificateService.generateDefaultGOSTSelfSignedCertificate("CN=TEST", 365);
X509Certificate certificate  = ca.getCertificate();
PrivateKey privateKey = ca.getPrivateKey();
X509CRL crl = CertificateService.generateCertificateRevocationList(ca.getCertificate(),ca.getPrivateKey(),null,14);
```

### Build user certificate
- Signature is:
    - 1.2.643.7.1.1.3.2
    - id-tc26-signwithdigest-gost3410-12-256
    - алгоритм подписи ГОСТ Р 34.10-2012 с ключом 256 с хэшированием ГОСТ Р 34.11-2012
- GOST EC Key curve is:
    - 1.2.643.7.1.2.1.1.1
    - id-tc26-gost-3410-12-256-paramSetA
    - рабочие параметры А алгоритма подписи ГОСТ Р 34.10-2012 с ключом 256
```java
CertificatePrivateKeyPair user = CertificateService.generateGOSTCertificate(
                "1.2.643.3.131.1.1=075305894589,CN=ФизЛицо, surname=Ivanov",
                ca.getCertificate(),
                ca.getPrivateKey(),
                null, //CryptoTools.DEFAULT_GOST_SIGNATURE
                "http://localhost:8080/cert.cer",
                "http://localhost:8080/cert/ocsp",
                "http://localhost:8080/cert.crl",
                15,
                List.of(KeyPurposeId.id_kp_clientAuth),
                365
        );
```

### Open CryptoPro pfx container, sign document and save to file
```java
byte[] pfx = Files.readAllBytes(Path.of("file.pfx"));
Map<String,CertificatePrivateKeyPair> pairs = ContainerService.readPfxContainer(pfx, "SomePassword");
CertificatePrivateKeyPair pair = pairs.values().iterator().next();

byte[] document = Files.readAllBytes(Path.of("doc.pdf"));
byte[] sig = SignService.signData(pair.getCertificate(),pair.getPrivateKey(),null,document,true);
Files.write(Path.of("document.sig"),sig, StandardOpenOption.CREATE)
```

