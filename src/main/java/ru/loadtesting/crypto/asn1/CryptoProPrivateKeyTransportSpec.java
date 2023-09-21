package ru.loadtesting.crypto.asn1;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.*;

@AllArgsConstructor
@Getter
/*
  We do not parse all ASN1Sequence elements. Extracting only some of them. It is enough to build private key.
 */
public class CryptoProPrivateKeyTransportSpec {

    private ASN1Integer version;
    private ASN1ObjectIdentifier algorithmIdentifier;
    private KeyDetails key;


    public static CryptoProPrivateKeyTransportSpec getInstance(byte[] key){
        ASN1Sequence sequence = ASN1Sequence.getInstance(key);
        ASN1Integer version = (ASN1Integer) sequence.getObjectAt(0);
        DLSequence alg_seq = (DLSequence) sequence.getObjectAt(1);
        ASN1ObjectIdentifier alg_id = (ASN1ObjectIdentifier) alg_seq.getObjectAt(0);
        //we ignore "(DLTaggedObject) sequence.getObjectAt(3); => szOID_CryptoPro_private_keys_extension_container_exchange_key_usage_period" because it is not neccessry for testing

        DEROctetString string = (DEROctetString) sequence.getObjectAt(2);
        byte[] value = string.getOctets();
        byte[] keyDetails = new byte[value.length-16];
        System.arraycopy(value,16,keyDetails,0,keyDetails.length);
        return new CryptoProPrivateKeyTransportSpec(version,alg_id,new KeyDetails(keyDetails));
    }

    public Integer getIntVersion(){
        return version.intPositiveValueExact();
    }

    public String getAlgorithm(){
        return algorithmIdentifier.getId();
    }

    @AllArgsConstructor
    @Getter
    public static class KeyDetails{
        private byte[] UKM;
        private byte[] CEK_ENC;
        private byte[] CEK_MAC;
        private ASN1ObjectIdentifier params;
        private ASN1ObjectIdentifier digest;
        private ASN1ObjectIdentifier algorithm;

        public KeyDetails (byte[] data){
            ASN1Sequence sequence = ASN1Sequence.getInstance(data);
            DLSequence transport = (DLSequence) sequence.getObjectAt(0);
            UKM = ((DEROctetString) transport.getObjectAt(0)).getOctets();
            DLSequence CEK_SEQUENCE = (DLSequence) transport.getObjectAt(1);
            CEK_ENC = ((DEROctetString) CEK_SEQUENCE.getObjectAt(0)).getOctets();
            CEK_MAC = ((DEROctetString) CEK_SEQUENCE.getObjectAt(1)).getOctets();

            DLTaggedObject algorithmsDetails = (DLTaggedObject) transport.getObjectAt(2);
            DLSequence algorithms = (DLSequence) algorithmsDetails.getBaseObject();
            DLTaggedObject l1 = (DLTaggedObject) algorithms.getObjectAt(1);
            DLSequence l2 = (DLSequence) l1.getBaseObject();
            DLSequence l3 = (DLSequence) l2.getObjectAt(1);
            algorithm = (ASN1ObjectIdentifier) l2.getObjectAt(0);
            params = (ASN1ObjectIdentifier) l3.getObjectAt(0);
            digest = (ASN1ObjectIdentifier) l3.getObjectAt(1);

        }


    }


}
