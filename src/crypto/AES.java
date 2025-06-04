package crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AES implements Cryptography {
    @Override
    public byte[] encrypt(CryptoData cryptoData, CryptoMode mode) throws NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher encryptCipher;
        IvParameterSpec iv;

        switch (mode) {
            case ECB:
                try {
                    encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cryptoData.getKey(), "AES"));
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                break;
            case CBC:
                try {
                    encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    iv = cryptoData.Iv;
                    encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cryptoData.getKey(), "AES"), iv);
                } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }
                break;
            default:
                throw new UnsupportedOperationException("Unsupported encryption mode");
        }

        return encryptCipher.doFinal(cryptoData.data);
    }

    @Override
    public byte[] decrypt(CryptoData cryptoData, CryptoMode mode) throws NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher decryptCipher;
        IvParameterSpec iv = null;

        switch (mode) {
            case CryptoMode.ECB:
                try {
                    decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cryptoData.getKey(), "AES"));
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                }
                break;
            case CryptoMode.CBC:
                try {
                    decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                    iv = cryptoData.Iv;
                    decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cryptoData.getKey(), "AES"), iv);
                } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
                    throw new RuntimeException(e);
                }
                break;
            default:
                throw new UnsupportedOperationException("Unsupported decryption mode");
        }

        return decryptCipher.doFinal(cryptoData.data);
    }

    @Override
    public int getKeySize() {
        return 128;
    }

    @Override
    public SecretKey getRandomSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(getKeySize());
        return keyGen.generateKey();
    }
}