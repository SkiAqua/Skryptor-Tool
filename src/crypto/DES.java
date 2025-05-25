package crypto;

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
		return 32;
	}
}
