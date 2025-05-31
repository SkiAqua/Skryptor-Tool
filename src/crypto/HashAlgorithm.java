package crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashAlgorithm {
	public static byte[] sha256(byte[] input) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] genericMessageDigest(byte[] input, String algorithm) throws NoSuchAlgorithmException {
		return MessageDigest.getInstance(algorithm).digest(input);
	}
}
