package ru.loadtesting.crypto.store;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Getter
@AllArgsConstructor
@EqualsAndHashCode
public class CertificatePrivateKeyPair {
    private X509Certificate certificate;
    private PrivateKey privateKey;
}
