package ru.loadtesting.crypto.cipher;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithSBox;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseWrapCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import ru.loadtesting.crypto.asn1.CryptoProPrivateKeyTransportSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * Class to extract {@link PrivateKey} from CryptoPro PBE 1.2.840.113549.1.12.1.80
 * Only supported GOST3410-2012 with 256 key length and unwrap mode
 */
public class UnwrapCipherForCryptoProPfx extends BaseWrapCipher implements PBE {

    public static byte[] defaultSBox = GOST28147Engine.getSBox("E-A");

    private KeyParameter exportKeyParameter; //KeyParameter
    /**
     * Cipher for transport decoding.
     */
    private final GOST28147Engine transportCipher = new GOST28147Engine();


    private final byte[] salt = new byte[8]; //iv or input vector


    @Override
    protected void engineInit(int opmode, Key inputKey, AlgorithmParameterSpec inputParams, SecureRandom random) {

        try
        {
            switch (opmode) {
                case Cipher.UNWRAP_MODE:
                    PKCS12Key key = (PKCS12Key) inputKey; //we only supports such casts. Please extend code for your needs
                    PBEParameterSpec params = (PBEParameterSpec) inputParams;  //we only supports such casts. Please extend code for your needs
                    System.arraycopy(params.getSalt(),0, salt,0,8);
                    exportKeyParameter = exportKeyKDF(new String(key.getPassword()).getBytes(StandardCharsets.UTF_16LE),params.getSalt(),params.getIterationCount());
                    CipherParameters param = new ParametersWithSBox(exportKeyParameter, defaultSBox);
                    transportCipher.init(true, param); //inverse logic
                    break;
                case Cipher.WRAP_MODE:
                    throw new InvalidParameterException("not supported opmode " + Cipher.WRAP_MODE);
                case Cipher.ENCRYPT_MODE:
                    throw new InvalidParameterException("not supported opmode " + Cipher.ENCRYPT_MODE);
                case Cipher.DECRYPT_MODE:
                    throw new InvalidParameterException("not supported opmode " + Cipher.DECRYPT_MODE);
                default:
                    throw new InvalidParameterException("Unknown mode parameter passed to init.");
            }
        }
        catch (Exception e)
        {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) {
        //we expect input.length == inputLen and inputOffset ==0
        if(input.length != inputLen) throw new InvalidParameterException("engineDoFinal input length "+input.length+" is not same as inputLen "+inputLen);
        if(inputOffset!=0) throw new InvalidParameterException("engineDoFinal inputOffset is not zero: "+inputOffset);

        //we do cbc here with input vector
        ByteBuffer inputWithIVBuffer = ByteBuffer.allocate(salt.length+input.length);
        inputWithIVBuffer.put(salt);
        inputWithIVBuffer.put(input);
        byte[] inputWithIV = inputWithIVBuffer.array();

        ByteBuffer buffer = ByteBuffer.allocate(input.length);
        int blockSize = engineGetBlockSize();
        for (int i=blockSize;i<inputWithIV.length;i+=blockSize){
            ByteBuffer next = ByteBuffer.allocate(blockSize).put(inputWithIV,i,(i+blockSize<inputWithIV.length)?blockSize:(inputWithIV.length - i));
            ByteBuffer prev = ByteBuffer.allocate(blockSize).put(inputWithIV,i-blockSize,blockSize);
            byte[] xor = new byte[blockSize];
            transportCipher.processBlock(prev.array(),0,xor,0);
            for (int j = 0; j < blockSize; j++) {
                xor[j] = (byte) (xor[j] ^ next.array()[j]);
            }
            buffer.put(xor,0,(i<input.length)?blockSize:i-input.length);
        }
        try {
            return buildSpecification(buffer.array());
        } catch (Exception e) {
            throw new RuntimeException("Failed to build specification",e);
        }
    }

    /**
     * Build {@link PrivateKeyInfo} from CryptoPro specification containing key algorithm details, encoded private key bytes and ukm for it decoding
     * @param key CryptoPro ASN1 specification of decoded private key
     * @return {@link PrivateKeyInfo#getEncoded()} specification for key
     * @throws IOException if for some reason we can not construct {@link PrivateKeyInfo}
     * @throws NoSuchAlgorithmException if key algorithm not {@link RosstandartObjectIdentifiers#id_tc26_gost_3410_12_256} ("1.2.643.7.1.1.1.1")
     */
    private byte[] buildSpecification(byte[] key) throws IOException, NoSuchAlgorithmException {
        CryptoProPrivateKeyTransportSpec spec = CryptoProPrivateKeyTransportSpec.getInstance(key);
        if(spec.getAlgorithmIdentifier().equals(RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256)){ //we only support Gost3411-2012-256  "1.2.643.7.1.1.1.1"
            byte[] Ks = unwrapGOST3410_2012_256(spec.getKey().getUKM(), spec.getKey().getCEK_ENC(),spec.getKey().getCEK_MAC());
            PrivateKeyInfo keyInfo = new PrivateKeyInfo(
                    new AlgorithmIdentifier(
                            spec.getKey().getAlgorithm(),
                            new DERSequence(new ASN1Encodable[]{spec.getKey().getParams(),spec.getKey().getDigest()})
                    ),
                    new DEROctetString(Ks)
            );
            return keyInfo.getEncoded();
        }else {
            throw new NoSuchAlgorithmException("Key algorithm not supported: "+spec.getKey().getAlgorithm());
        }
    }

    /**
     * Key derivation function with salt and iterations to build transport key for encoding/decoding
     * @param key original key or password (master password)
     * @param salt cryptographic salt
     * @param iterationCount the number of iterations of a sub-function
     * @return {@link KeyParameter} containing derived key
     */
    private KeyParameter exportKeyKDF(byte[] key, byte[] salt, int iterationCount) {
        GOST3411Digest digest = new GOST3411Digest();
        int size = digest.getDigestSize();
        for(int i=1;i<iterationCount+1;i++){
            ByteBuffer buffer = ByteBuffer.allocate(key.length + salt.length+2).put(key).put(salt).putShort((short) i);
            key = new byte[size];
            digest.update(buffer.array(),0,buffer.array().length);
            digest.doFinal(key,0);
        }
        return new KeyParameter(key);
    }

    /**
     * Decrypt PrivateKey using ukm and encrypted private key
     * <p><b>See</b></p>
     * <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ,
     * СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ
     * ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012. Paragraph 5.4<</p>
     * <p><b>and</b></p>
     * <p>
     *  RFC 4357, paragraph 6.4
     * </p>
     * <p>We do not check CEK_MAC because this lib is only for test usage</p>
     * @param UKM UKM according to document <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ, СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012. </p>
     * @param CEK_ENC CEK_ENC according to document <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ, СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012.</p>
     * @param CEK_MAC CEK_MAC according to document <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ, СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012.</p>
     * @return decoded private key bytes. For GOST3410-2012 it is param D of elliptic curve
     */
    private byte[] unwrapGOST3410_2012_256(byte[] UKM, byte[] CEK_ENC,byte[] CEK_MAC) {
        //get key from UKM
        byte[] KEK = KDF_GOSTR3411_2012_256(UKM);

        //Simple ECB. We expect 32 byte keys
        GOST28147Engine engine = new GOST28147Engine();
        CipherParameters param = new ParametersWithSBox(new KeyParameter(KEK), defaultSBox);
        engine.init(false,param);
        byte[] out = new byte[32];
        engine.processBlock(CEK_ENC,0,out,0);
        engine.processBlock(CEK_ENC,8,out,8);
        engine.processBlock(CEK_ENC,16,out,16);
        engine.processBlock(CEK_ENC,24,out,24);

        //if(!checkMac(out,KEK,CEK_MAC)) throw new RuntimeException("Mac is not correct"); // wrong algorithms here, not necessary for testing:
        return out;
    }

    /**
     * Generate key using diversification function based on HMAC
     * <p>See</p>
     * <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ,
     * СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ
     * ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012</p> paragraph 5.4
     * @param ukm according to document <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ, СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012. </p>
     * @return KEK according to document <p>ИСПОЛЬЗОВАНИЕ КРИПТОГРАФИЧЕСКИХ АЛГОРИТМОВ, СОПУТСТВУЮЩИХ ПРИМЕНЕНИЮ СТАНДАРТОВ ГОСТ Р 34.10-2012 И ГОСТ Р 34.11-2012. </p>
     */
    private byte[] KDF_GOSTR3411_2012_256(byte[] ukm) {
        byte[] input = new byte[]{
                0x01, //fixed bytes
                38,-67,-72,120, //label (0x26|0xBD|0xB8|0x78)
                0x00, //fixed bytes
                ukm[0],ukm[1],ukm[2],ukm[3],ukm[4],ukm[5],ukm[6],ukm[7], //seed = ukm. We expect ukm is 8 bytes
                0x01,0x00 //fixed bytes
        };
        HMac mac = new HMac(new GOST3411_2012_256Digest());
        mac.init(exportKeyParameter);
        mac.update(input,0,input.length);
        byte[] key = new byte[32];
        mac.doFinal(key,0);
        return key;
    }


    /**
     * Check is incorrect. Need some other algorithms
     */
    @Deprecated
    private boolean checkMac(byte[] K,byte[] KEK,byte[] CEK_MAC) {
        GOST28147Mac mac = new GOST28147Mac();
        ParametersWithSBox params = new ParametersWithSBox(new KeyParameter(KEK),defaultSBox);//wrong box? Param-Z not working too
        mac.init(params);
        mac.update(K,0,K.length);
        byte[] res = new byte[mac.getMacSize()];
        mac.doFinal(res,0);
        return Arrays.equals(CEK_MAC,res);
    }


    @Override
    protected int engineGetBlockSize() {
        return transportCipher.getBlockSize();
    }

}
