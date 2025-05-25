package crypto;

import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class CryptoData {
    public byte[] data;
    public byte[] cryptoKey;
    public IvParameterSpec Iv;

    public CryptoData(byte[] newData, byte[] newCryptoKey, IvParameterSpec newIV) {
        data = newData;
        cryptoKey = newCryptoKey;
        Iv = newIV;
    }

    public CryptoData(byte[] newData, byte[] newCryptoKey) {
        this(newData, newCryptoKey, getRandomIvSpec());
    }

    public byte[] getDerivedKey(int keySize) throws UnsupportedOperationException, NoSuchAlgorithmException {
        byte[] derivedKey;

        if (keySize <= 32) {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] shaDigest = sha256.digest(cryptoKey);
            derivedKey = Arrays.copyOf(shaDigest, keySize);
        } else {
            throw new UnsupportedOperationException("Value must be under 32 bytes.");
        }

        return derivedKey;
    }

    public static IvParameterSpec getRandomIvSpec() {
        IvParameterSpec newIv;
        byte[] ivBytes = new byte[16];

        new SecureRandom().nextBytes(ivBytes);

        newIv = new IvParameterSpec(ivBytes);

        return newIv;
    }
}
