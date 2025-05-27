package skryptorTool;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.event.ActionEvent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import crypto.*;

import javax.crypto.spec.IvParameterSpec;

public class VisualInterfaceController {
	// Crypto Tab

	private byte[] keyBytes = new byte[256];

	Map<String, Cryptography> cryptographyMap = Map.ofEntries(
			Map.entry("AES-256", new AES256()),
			Map.entry("AES", new AES()),
			Map.entry("DES", new DES())
	);
	private Cryptography currentCryptoAlgorithm;

	private final Cryptography.CryptoMode defaultCryptoMode = Cryptography.CryptoMode.CBC;

	@FXML
	private ComboBox<String> cryptoAlgorithm_ComboBox;
	@FXML
	private Button loadFileKey_Button;
	@FXML
	private Button genRandomKey_Button;
	@FXML
	private TextField secretKey_TextField;
	@FXML
	private Button loadFileToEncrypt_Button;
	@FXML
	private TextArea plainText_TextArea;
	@FXML
	private Button loadFileToDecrypt_Button;
	@FXML
	private TextArea cipherText_TextArea;

	// Hash Tab

	// Authentication Tab

	@FXML
	public void encryptText(ActionEvent event) throws UnsupportedEncodingException, IOException {
		// Check if the encryption algorithm is not null
		if (cryptoAlgorithm_ComboBox.getValue() == null)
				return;

		// Get the data
		byte[] plainTextBytes = plainText_TextArea.getText().getBytes(StandardCharsets.UTF_8);
		byte[] encryptionKey;
		byte[] cipherBytes;

		if (keyBytes == null)
			encryptionKey = secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);
		else
			encryptionKey = Arrays.copyOf(keyBytes, keyBytes.length);

		CryptoData cryptoData = new CryptoData(plainTextBytes, encryptionKey);

		// Check if the data is null
		if (plainTextBytes.length == 0 || encryptionKey.length == 0) {
			return;
		}

		// Encryption
		try {
			cipherBytes = currentCryptoAlgorithm.encrypt(cryptoData, Cryptography.CryptoMode.CBC);
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		// Concatenate Inicialization Vector with the CipherText
		ByteArrayOutputStream IvPlusCipherBytes = new ByteArrayOutputStream();
		IvPlusCipherBytes.write(cryptoData.Iv.getIV());
		IvPlusCipherBytes.write(cipherBytes);

		//Return
		cipherText_TextArea.setText(Base64.getEncoder().encodeToString(IvPlusCipherBytes.toByteArray()));
	}

	@FXML
	public void decryptText(ActionEvent event) {
		// Verifica se o usuário escolheu um algorítmo de criptografia.
		if (cryptoAlgorithm_ComboBox.getValue() == null)
			return;

		if (cipherText_TextArea.getText().length() <= 16) {
			showErrorMessage("Texto cifrado inválido.");
			return;
		}
		byte[] IvPlusCipherBytes = Base64.getDecoder().decode(cipherText_TextArea.getText().getBytes(StandardCharsets.UTF_8));
		byte[] ivBytes = Arrays.copyOfRange(IvPlusCipherBytes, 0,16);

		IvParameterSpec ivParameter = new IvParameterSpec(ivBytes);

		byte[] cipherBytes = Arrays.copyOfRange(IvPlusCipherBytes, 16, IvPlusCipherBytes.length);
		byte[] decryptionKey;
		byte[] plainBytes;

		if (keyBytes == null)
			decryptionKey = secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);
		else
			decryptionKey = Arrays.copyOf(keyBytes, keyBytes.length);

		if (cipherBytes.length == 0 || decryptionKey.length == 0) {
			return;
		}

		try {
			plainBytes = currentCryptoAlgorithm.decrypt(new CryptoData(cipherBytes, decryptionKey,ivParameter), Cryptography.CryptoMode.CBC);
		} catch (IllegalBlockSizeException e) {
			showErrorMessage("Texto cifrado inválido.");
			return;
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getClass().getSimpleName() + " " + e.getMessage());
			return;
		}

		plainText_TextArea.setText(new String(plainBytes, StandardCharsets.UTF_8));
	}
	@FXML
	public void generateRandomKey(ActionEvent event) {
		if (currentCryptoAlgorithm == null)
			return;

		byte[] newRandomKey;

		try {
			newRandomKey = currentCryptoAlgorithm.getRandomSecretKey().getEncoded();
		} catch (java.security.NoSuchAlgorithmException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		StringBuilder hexKey = new StringBuilder();
		for (byte b : newRandomKey) {
			hexKey.append(String.format("%02X", b));
		}

		secretKey_TextField.setText(hexKey.toString());
	}
	@FXML
	public void switchText() {
		String plainText = plainText_TextArea.getText();
		plainText_TextArea.setText(cipherText_TextArea.getText());
		cipherText_TextArea.setText(plainText);
	}
	@FXML
	public void updateCurrentCryptographyAlgorithm(ActionEvent event) {
		currentCryptoAlgorithm = cryptographyMap.get(cryptoAlgorithm_ComboBox.getValue());
	}
	@FXML
	public void showInformationMessage(ActionEvent event) {
		Alert infoAlert = new Alert(Alert.AlertType.INFORMATION);
		infoAlert.setTitle("Criptografia de texto.");
		infoAlert.setHeaderText(null);
		infoAlert.setContentText("Codificado usando Base64 para representação dos bytes em texto.\nIV está nos primeiros 16 bytes.\nA chave real de criptografia é derivada aplicando SHA-256 sobre o valor do campo 'Chave Secreta'.");
		infoAlert.showAndWait();
	}
	public void initialize() {
		cryptoAlgorithm_ComboBox.getItems().addAll(cryptographyMap.keySet());
	}

	public void showErrorMessage(String message) {
		System.out.println(message);
		Alert alert = new Alert(Alert.AlertType.ERROR);
		alert.setTitle("Erro!");
		alert.setContentText(message);
		alert.showAndWait();
	}
}
