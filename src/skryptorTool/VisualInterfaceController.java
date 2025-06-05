package skryptorTool;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.event.ActionEvent;
import javafx.stage.FileChooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import crypto.*;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class VisualInterfaceController {
	// Crypto Tab

	private byte[] keyBytes;

	Map<String, Cryptography> cryptographyMap = Map.ofEntries(
			Map.entry("AES-256", new AES256()),
			Map.entry("AES", new AES()),
			Map.entry("DES", new DES())
	);
	private Cryptography currentCryptoAlgorithm;

	private final Cryptography.CryptoMode defaultCryptoMode = Cryptography.CryptoMode.CBC;
	private boolean forcePadding = true;

	@FXML
	private ComboBox<String> cryptoAlgorithm_ComboBox;
	@FXML
	private Button loadFileKey_Button;
	@FXML
	private Button genRandomKey_Button;
	@FXML
	private CheckBox forceHash_CheckBox;
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
	@FXML
	private ComboBox<String> hashAlgorithm_ComboBox;

	private final ObservableList<String> hashAlgorithms = FXCollections.observableArrayList("SHA-1", "MD5", "SHA-256", "SHA-384", "SHA-512");

	private byte[] hashFileBytes;

	@FXML
	private TextField hashInput_TextField;

	@FXML
	private TextArea hashOutput_TextArea;

	@FXML
	private Button hashInput_Button;

	@FXML
	private void generateHash() {
		String selectedHashAlgorithm = hashAlgorithm_ComboBox.getSelectionModel().getSelectedItem();

		byte[] hashInput;
		byte[] hashOutput;


		if (hashFileBytes == null)
			hashInput = hashInput_TextField.getText().getBytes();
		else
			hashInput = Arrays.copyOfRange(hashFileBytes, 0, hashFileBytes.length);

		if (selectedHashAlgorithm == null || hashInput.length == 0) {
			System.out.println("selectedHashAlgorithm is null or hashInput is empty");
			return;
		}

		try {
			hashOutput = HashAlgorithm.genericMessageDigest(hashInput, selectedHashAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			showErrorMessage("Algorítmo de hash não existe!");
			return;
		}

		StringBuilder sb = new StringBuilder();

		for (byte b : hashOutput) {
			sb.append(String.format("%02x", b));
		}

		hashOutput_TextArea.setText(sb.toString());
	}
	@FXML
	private void loadFileToGenerateHash() {
		if (hashFileBytes != null) {
			hashFileBytes = null;
			hashInput_Button.setText("\uD83D\uDCC1");
			hashInput_TextField.setText("");
			hashInput_TextField.setDisable(false);
			return;
		}
		String selectedHashAlgorithm = hashAlgorithm_ComboBox.getSelectionModel().getSelectedItem();

		File hashFile = getAnyFile();

		if (hashFile == null)
			return;

		try {
			hashFileBytes = HashAlgorithm.genericMessageDigest(Files.readAllBytes(hashFile.toPath()), selectedHashAlgorithm);
		} catch(IOException | NoSuchAlgorithmException e) {
			showErrorMessage("Não foi possível abrir o arquivo.");
			hashFileBytes = null;
			return;
		}

		hashInput_Button.setText("❌");
		hashInput_TextField.setText(hashFile.getAbsolutePath());
		hashInput_TextField.setDisable(true);

	}
	// Authentication Tab

	//
	@FXML
	public void loadFileAsKey(ActionEvent event) {
		if (keyBytes != null) {
			keyBytes = null;
			loadFileKey_Button.setText("\uD83D\uDCC1");
			secretKey_TextField.setText("");
			forceHash_CheckBox.setSelected(false);
			secretKey_TextField.setDisable(false);
			genRandomKey_Button.setDisable(false);
			forceHash_CheckBox.setDisable(false);
		} else {

			File f = getAnyFile();

			if (f == null)
				return;

			try {
				keyBytes = Files.readAllBytes(f.toPath());
				keyBytes = HashAlgorithm.sha256(keyBytes);
			} catch (IOException e) {
				showErrorMessage("Erro ao ler o arquivo!");
				return;
			} catch (OutOfMemoryError e) {
				showErrorMessage("Esse arquivo é muito grande!");
				return;
			}


			secretKey_TextField.setText(f.getAbsolutePath());
			forceHash_CheckBox.setSelected(true);
			loadFileKey_Button.setText("❌");
			secretKey_TextField.setDisable(true);
			genRandomKey_Button.setDisable(true);
			forceHash_CheckBox.setDisable(true);
		}
	}
	@FXML
	public void loadFileAndEncrypt(ActionEvent event) {
		if (cryptoAlgorithm_ComboBox.getValue() == null || secretKey_TextField.getText().isEmpty())
			return;

		File f = getAnyFile();

		if (f == null)
			return;

		byte[] fileBytes;
		byte[] cipherBytes;
		byte[] encryptionKey;

		encryptionKey = (keyBytes != null)
				? Arrays.copyOf(keyBytes, keyBytes.length)
				: secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);

		try {
			fileBytes = Files.readAllBytes(f.toPath());
		} catch (IOException e) {
			showErrorMessage("Erro ao ler o arquivo!");
			return;
		} catch (OutOfMemoryError e) {
			showErrorMessage("Esse arquivo é muito grande!");
			return;
		}

		CryptoData cryptoData = new CryptoData(fileBytes, encryptionKey);

		if (forceHash_CheckBox.isSelected())
			cryptoData.setPadding(currentCryptoAlgorithm.getKeySize()/8);

		try {
			cipherBytes = currentCryptoAlgorithm.encrypt(cryptoData, Cryptography.CryptoMode.CBC);
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		ByteArrayOutputStream ivPlusCipherBytes;

		try {
			// Concatenate Inicialization Vector with the CipherText
			ivPlusCipherBytes = new ByteArrayOutputStream();
			ivPlusCipherBytes.write(cryptoData.Iv.getIV());
			ivPlusCipherBytes.write(cipherBytes);
		} catch (IOException e) {
			showErrorMessage("Erro ao escrever o arquivo!");
			return;
		}
		try {
			Files.write(Path.of(f.getAbsolutePath() + ".bin"), ivPlusCipherBytes.toByteArray(), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		Alert finishAlert = new Alert(Alert.AlertType.INFORMATION);
		finishAlert.setTitle("Sucesso");
		finishAlert.setHeaderText(null);
		finishAlert.setContentText("A encriptografia foi bem sucedida!");
		finishAlert.show();
	}
	@FXML public void loadFileAndDecrypt(ActionEvent event) {
		if (cryptoAlgorithm_ComboBox.getValue() == null || secretKey_TextField.getText().isEmpty())
			return;

		File f = getAnyFile();

		byte[] fileBytes;
		byte[] plainBytes;
		byte[] decryptionKey;

		try {
			fileBytes = Files.readAllBytes(f.toPath());
		} catch (IOException e) {
			showErrorMessage("Erro ao ler o arquivo!");
			return;
		} catch (OutOfMemoryError e) {
			showErrorMessage("Esse arquivo é muito grande!");
			return;
		}

		if (fileBytes.length <= 16) {
			showErrorMessage("Arquivo cifrado inválido.");
			return;
		}

		byte[] cipherBytes = Arrays.copyOfRange(fileBytes, 16, fileBytes.length);
		byte[] ivBytes = Arrays.copyOfRange(fileBytes, 0,16);

		IvParameterSpec ivParameter = new IvParameterSpec(ivBytes);

		decryptionKey = (keyBytes != null)
				? Arrays.copyOf(keyBytes, keyBytes.length)
				: secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);

		CryptoData cryptoData = new CryptoData(cipherBytes, decryptionKey, ivParameter);

		if (forceHash_CheckBox.isSelected())
			cryptoData.setPadding(currentCryptoAlgorithm.getKeySize()/8);

		try {
			plainBytes = currentCryptoAlgorithm.decrypt(cryptoData, Cryptography.CryptoMode.CBC);
		} catch (GeneralSecurityException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		String decryptedFilePath = Path.of(f.getAbsolutePath()).toString();

		if (decryptedFilePath.endsWith(".bin"))
			decryptedFilePath = decryptedFilePath.substring(0, decryptedFilePath.length() - 4);

		try {
			Files.write(Paths.get(decryptedFilePath), plainBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
		} catch (IOException e) {
			showErrorMessage(e.getMessage());
			return;
		}

		Alert finishAlert = new Alert(Alert.AlertType.INFORMATION);
		finishAlert.setTitle("Sucesso");
		finishAlert.setHeaderText(null);
		finishAlert.setContentText("A descriptografia foi bem sucedida!");
		finishAlert.show();
	}
	@FXML
	public void encryptText(ActionEvent event) throws UnsupportedEncodingException, IOException {
		// Check if the encryption algorithm is not null
		if (cryptoAlgorithm_ComboBox.getValue() == null)
				return;

		// Get the data
		byte[] plainTextBytes = plainText_TextArea.getText().getBytes(StandardCharsets.UTF_8);
		byte[] encryptionKey;
		byte[] cipherBytes;

		encryptionKey = (keyBytes != null) ? Arrays.copyOf(keyBytes, keyBytes.length) : secretKey_TextField.getText().getBytes(StandardCharsets.UTF_8);

		CryptoData cryptoData = new CryptoData(plainTextBytes, encryptionKey);

		System.out.println(currentCryptoAlgorithm.getKeySize()/8);
		if (forceHash_CheckBox.isSelected())
			cryptoData.setPadding(currentCryptoAlgorithm.getKeySize()/8);

		// Check if the data is null
		if (plainTextBytes.length == 0 || encryptionKey.length == 0) {
			return;
		}

		// Encryption
		try {
			cipherBytes = currentCryptoAlgorithm.encrypt(cryptoData, Cryptography.CryptoMode.CBC);
		} catch (InvalidKeyException e) {
			showErrorMessage("Chave inválida, considere forçar o hash.");
			return;
		} catch (GeneralSecurityException e) {
			showErrorMessage(e);
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

		CryptoData cryptoData = new CryptoData(cipherBytes, decryptionKey, ivParameter);

		if (forceHash_CheckBox.isSelected())
			cryptoData.setPadding(currentCryptoAlgorithm.getKeySize()/8);

		try {
			plainBytes = currentCryptoAlgorithm.decrypt(cryptoData, Cryptography.CryptoMode.CBC);
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
		hashAlgorithm_ComboBox.getItems().addAll(hashAlgorithms);
	}
	public File getAnyFile() {
		FileChooser fileChooser = new FileChooser();
		fileChooser.setTitle("Selecione um arquivo");
		return fileChooser.showOpenDialog(null);
	}
	public void showErrorMessage(String message) {
		System.out.println(message);
		Alert alert = new Alert(Alert.AlertType.ERROR);
		alert.setTitle("Erro!");
		alert.setContentText(message);
		alert.showAndWait();
	}

	public void showErrorMessage(Exception e) {
		String errorMessage = String.format("%s: %s", e.getClass().getSimpleName(), e.getMessage());
		System.out.println(errorMessage);
		showErrorMessage(errorMessage);
	}
}
