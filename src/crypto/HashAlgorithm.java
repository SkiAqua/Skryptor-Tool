package crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashAlgorithm {
	public static byte[] sha256(byte[] input) throws NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		return sha256.digest(input);

	}
}
