package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public class AES256 implements Cryptography {
	@Override
	public byte[] encrypt(CryptoData cryptoData, CryptoMode mode) throws GeneralSecurityException {
		Cipher encryptCipher;
		IvParameterSpec iv;

		switch (mode) {
			case ECB:
				encryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cryptoData.getDerivedKey(32), "AES"));
				break;
			case CBC:
				encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				iv = cryptoData.Iv;
				encryptCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cryptoData.getDerivedKey(32), "AES"), iv);
				break;
			default:
				throw new GeneralSecurityException("Unsupported encryption mode");
		}

		return encryptCipher.doFinal(cryptoData.data);
	}

	@Override
	public byte[] decrypt(CryptoData cryptoData, CryptoMode mode) throws GeneralSecurityException {
		Cipher decryptCipher;
		IvParameterSpec iv = null;

		switch (mode) {
			case CryptoMode.ECB:
				decryptCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				break;
			case CryptoMode.CBC:
				decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				iv = cryptoData.Iv;
				break;
			default:
				throw new GeneralSecurityException("Unsupported encryption mode");
		}

		if (iv == null)
			decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cryptoData.getDerivedKey(32), "AES"));
		else
			decryptCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cryptoData.getDerivedKey(32), "AES"), iv);

		return decryptCipher.doFinal(cryptoData.data);
	}

	@Override
	public int getKeySize() {
		return 256;
	}

	@Override
	public SecretKey getRandomSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(getKeySize());
		return keyGen.generateKey();
	}
}