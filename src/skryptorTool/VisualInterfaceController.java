package skryptorTool;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.event.ActionEvent;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Map;

import crypto.*;

public class VisualInterfaceController {
	// Crypto Tab
	Map<String, Cryptography> cryptographyMap = Map.ofEntries(
			Map.entry("AES", new AES()),
			Map.entry("DES", new DES())
	);
	private Cryptography currentCryptoAlgorithm;

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
	public void encryptText(ActionEvent event) throws UnsupportedEncodingException {
		if (cryptoAlgorithm_ComboBox.getValue() == null)
				return;
		currentCryptoAlgorithm = cryptographyMap.get(cryptoAlgorithm_ComboBox.getValue());

		byte[] plainTextBytes = plainText_TextArea.getText().getBytes(StandardCharsets.UTF_8);
		byte[] encryptionKey = secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);
		byte[] cipherBytes;

		if (plainTextBytes.length == 0 || encryptionKey.length == 0) {
			return;
		}

		try {
			cipherBytes = currentCryptoAlgorithm.encrypt(new CryptoData(plainTextBytes, encryptionKey), Cryptography.CryptoMode.CBC);
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		cipherText_TextArea.setText(Base64.getEncoder().encodeToString(cipherBytes));
	}

	@FXML
	public void decryptText(ActionEvent event) {
		if (cryptoAlgorithm_ComboBox.getValue() == null)
			return;

		currentCryptoAlgorithm = cryptographyMap.get(cryptoAlgorithm_ComboBox.getValue());

		byte[] cipherBytes = Base64.getDecoder().decode(cipherText_TextArea.getText());
		byte[] decryptionKey = secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);
		byte[] plainBytes;

		if (cipherBytes.length == 0 || decryptionKey.length == 0) {
			return;
		}

		try {
			plainBytes = currentCryptoAlgorithm.decrypt(new CryptoData(cipherBytes, decryptionKey), Cryptography.CryptoMode.CBC);
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		plainText_TextArea.setText(new String(plainBytes, StandardCharsets.UTF_8));
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
