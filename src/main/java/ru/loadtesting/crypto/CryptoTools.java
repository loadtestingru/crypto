package ru.loadtesting.crypto;

import lombok.extern.log4j.Log4j2;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import ru.loadtesting.crypto.cipher.UnwrapCipherForCryptoProPfx;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EllipticCurve;

@Log4j2
public class CryptoTools {

    //helpers
    public static final DefaultDigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

    //default algorithms
    public static final String DEFAULT_GOST_KEYPAIRGENERATOR = "ECGOST3410-2012";
    public static final String DEFAULT_GOST_SIGNATURE = "GOST3411WITHECGOST3410-2012-256";
    public static final String DEFAULT_GOST_CURVE = "Tc26-Gost-3410-12-256-paramSetA";

    /**
     * See {@link DefaultDigestAlgorithmIdentifierFinder} for other algorithms names
     */
    public static final String DEFAULT_GOST_DIGEST = "GOST3411-2012-256";



    static {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        provider.addAlgorithm("Cipher.1.2.840.113549.1.12.1.80", UnwrapCipherForCryptoProPfx.class.getName()); //crypto pro default algorithm
        Security.addProvider(provider);
    }

    public static String getProviderName(){
        return "BC";
    }


    /**
     * Find default algorithm for private key.
     * Only some algorithms are supported, so method need to be updated for your needs
     * @param privateKey privateKey to find possible signature algorithm
     * @return possible signature algorithms for provided private key if
     * @throws InvalidKeyException if we can not extract parameters from key
     */
    public static String getSignatureAlgorithms(PrivateKey privateKey) throws InvalidKeyException {
        switch (privateKey.getAlgorithm()){
            case "ECGOST3410":
                return "GOST3411WITHECGOST3410";
            case "ECGOST3410-2012":
                ECKeyParameters param = (ECKeyParameters) ECUtil.generatePrivateKeyParameter(privateKey);
                if(param.getParameters().getN().bitLength() >= 505) return "GOST3411WITHECGOST3410-2012-512";
                else if(param.getParameters().getN().bitLength() <=256 ) return "GOST3411WITHECGOST3410-2012-256";
                else throw new IllegalArgumentException("Key out of range for ECGOST3410-2012");
            case "ECDSA":
            case "EC":
                EllipticCurve curve = ((ECPrivateKey) privateKey).getParams().getCurve();
                switch (curve.getField().getFieldSize()) {
                    case 163:
                    case 176:
                    case 191:
                    case 192:
                    case 208:
                    case 224:
                        return "SHA224WITHECDDSA";
                    case 239:
                    case 256:
                        return "SHA256withECDSA";
                    case 272:
                    case 304:
                    case 359:
                    case 368:
                    case 384:
                        return "SHA384withECDSA";
                    case 431:
                    case 521:
                        return "SHA512withECDSA";
                    default:
                        throw new IllegalArgumentException("unknown elliptic curve: " + curve+". Field size: "+curve.getField().getFieldSize());
                }
            case "RSA":
                return "SHA256WithRSAEncryption";
            default:
                throw new UnsupportedOperationException("unsupported private key algorithm: " + privateKey.getAlgorithm());
        }
    }






}
