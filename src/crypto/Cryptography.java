package crypto;

import java.security.GeneralSecurityException;

public interface Cryptography {
    public static enum CryptoMode {
        ECB,
        CBC,
        CFB,
        OFB,
        CTR
    }

    // Encrypts Bytes
    byte[] encrypt(CryptoData cryptoData, CryptoMode mode) throws GeneralSecurityException;

    // Decrypts Bytes
    byte[] decrypt(CryptoData cryptoData, CryptoMode mode) throws GeneralSecurityException;

    int getKeySize();
}
