package crypto;

import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoData {
    public final byte[] data;
    public final byte[] cryptoKey;
    public final IvParameterSpec Iv;

    public CryptoData(byte[] newData, byte[] newCryptoKey, IvParameterSpec newIV) {
        data = newData;
        cryptoKey = newCryptoKey;
        Iv = newIV;
    }

    public CryptoData(byte[] newData, byte[] newCryptoKey) {
        this(newData, newCryptoKey, getRandomIvSpec());
    }

    public byte[] getDerivedKey(int keySize) {
        if (keySize < 16 || keySize > 32)
            throw new IllegalArgumentException("Value must be between 16 and 32 bytes.");

        byte[] shaDigest = HashAlgorithm.sha256(cryptoKey);
        return Arrays.copyOf(shaDigest, keySize);


    }

    public static IvParameterSpec getRandomIvSpec() {
        IvParameterSpec newIv;
        byte[] ivBytes = new byte[16];

        new SecureRandom().nextBytes(ivBytes);

        newIv = new IvParameterSpec(ivBytes);

        return newIv;
    }
}
