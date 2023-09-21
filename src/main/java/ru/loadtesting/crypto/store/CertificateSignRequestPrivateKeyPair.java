package ru.loadtesting.crypto.store;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.PrivateKey;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
public class CertificateSignRequestPrivateKeyPair {
    private PKCS10CertificationRequest request;
    private PrivateKey privateKey;
}
