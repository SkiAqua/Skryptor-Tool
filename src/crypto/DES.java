package crypto;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class DES implements Cryptography {
	@Override
	public byte[] encrypt(CryptoData cryptoData, CryptoMode mode) {
		System.out.println("encrypting DES...");
		return new byte[12];
	}
	@Override
	public byte[] decrypt(CryptoData cryptoData, CryptoMode mode) {
		System.out.println("decrypting DES...");
		return new byte[12];
	}
	@Override
	public int getKeySize() {
		return 56;
	}

	@Override
	public SecretKey getRandomSecretKey() throws NoSuchAlgorithmException {
		KeyGenerator keyGen = KeyGenerator.getInstance("DES");
		keyGen.init(getKeySize());
		return keyGen.generateKey();
	}
}
