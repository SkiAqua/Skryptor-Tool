package crypto;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoData {
    public final byte[] data;
    public final IvParameterSpec Iv;
    public int paddingSize;

    private final byte[] cryptoKey;
    private boolean forcePad = false;

    public CryptoData(byte[] newData, byte[] newCryptoKey, IvParameterSpec newIV) {
        data = newData;
        cryptoKey = newCryptoKey;
        Iv = newIV;
    }

    public CryptoData(byte[] newData, byte[] newCryptoKey) {
        this(newData, newCryptoKey, getRandomIvSpec());
    }

    public byte[] getKey() {
        if (!forcePad) {
            return cryptoKey;
        }

        byte[] shaDigest = HashAlgorithm.sha256(cryptoKey);

        return Arrays.copyOf(shaDigest, paddingSize);
    }
    public void setPadding(int paddingValue) {
        if (paddingValue < 7 || paddingValue > 32)
            throw new IllegalArgumentException(String.format("Padding must be between 7 and 32 bytes. (received %d)", paddingValue));

        forcePad = true;
        paddingSize = paddingValue;
    }

    public static IvParameterSpec getRandomIvSpec() {
        IvParameterSpec newIv;
        byte[] ivBytes = new byte[16];

        new SecureRandom().nextBytes(ivBytes);

        newIv = new IvParameterSpec(ivBytes);

        return newIv;
    }
}
