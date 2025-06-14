package crypto;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;

public interface Cryptography {
    enum CryptoMode {
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

    SecretKey getRandomSecretKey() throws NoSuchAlgorithmException;
}
