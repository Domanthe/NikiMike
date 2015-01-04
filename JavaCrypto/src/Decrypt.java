package crypto;

import java.io.*;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Decrypt {

	private static final String PATH_TO_CONFIGURATION_FILE = "C:\\Users\\Tal\\workspace\\JavaCrypto\\ConfigurationFile.txt";
	private static final String KEY_STORE_PASSWORD = "keystorepassword";
	
	private String keyStorePath;
	private String keyStoreAlias;
	private byte[] IV = new byte[16];
	private String encFileLoc;
	private byte[] encryptedSecretKey;
	private byte[] encSignature;
	private KeyStore keyStore;
	private String MessageEncryptAlgo;
	private String MessageEncryptAlgoProvider;
	private String KeyEncryptAlgo;
	private String KeyEncryptAlgoProvider;
	private String SignatureEncryptAlgo;
	private String SignatureEncryptAlgoProvider;
	private String SecretKeyAlgo;
	private String DigestAlgo;
	private String DigestAlgoProvider;
	private byte[] decryptedText = null;

	/**
	 * Constructor
	 * 
	 * @param configFileLocation
	 *            - Configuration file location
	 */
	public Decrypt(String configFileLocation) {

		// Extract parameters from file
		extractConfiguration(configFileLocation);

		// Load Key store
		loadKeyStore();
	}

	/**
	 * Load Key store and initiate variable
	 */
	private void loadKeyStore() {
		try {
			this.keyStore = KeyStore.getInstance("JKS");
			this.keyStore.load(new FileInputStream(this.keyStorePath),
					KEY_STORE_PASSWORD.toCharArray());
		} catch (Exception e) {
			System.out.println("Error: cannot load Key Store " + e.getMessage());
		}
	}

	/**
	 * Extract parameters from configuration file
	 * 
	 * @param configFilePath
	 *            - Configuration file location
	 */
	private void extractConfiguration(String configFilePath) {
		Properties fileOutputStream = new Properties();
		try {
			fileOutputStream.load(new FileReader(configFilePath));

			keyStorePath = fileOutputStream.getProperty("KeyStoreFile");
			keyStoreAlias = fileOutputStream.getProperty("KeyStoreAlias");
			IV = hexToByteArray(fileOutputStream.getProperty("IV"));
			encFileLoc = fileOutputStream.getProperty("EncryptedFileLocation");
			encryptedSecretKey = hexToByteArray(fileOutputStream
					.getProperty("EncryptedKey"));
			encSignature = hexToByteArray(fileOutputStream
					.getProperty("Signature"));
			MessageEncryptAlgo = fileOutputStream
					.getProperty("MessageEncryptAlgo");
			MessageEncryptAlgoProvider = fileOutputStream
					.getProperty("MessageEncryptAlgoProvider");
			KeyEncryptAlgo = fileOutputStream.getProperty("KeyEncryptAlgo");
			KeyEncryptAlgoProvider = fileOutputStream
					.getProperty("KeyEncryptAlgoProvider");
			SignatureEncryptAlgo = fileOutputStream
					.getProperty("SignatureEncryptAlgo");
			SignatureEncryptAlgoProvider = fileOutputStream
					.getProperty("SignatureEncryptAlgoProvider");
			SecretKeyAlgo = fileOutputStream.getProperty("SecretKeyAlgo");
			DigestAlgo = fileOutputStream.getProperty("DigestAlgo");
			DigestAlgoProvider = fileOutputStream
					.getProperty("DigestAlgoProvider");
		} catch (Exception e) {
			System.out.println("Error: cannot read the configuration file "
					+ e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Read file as bytes
	 * 
	 * @param file the file we are reading from
	 * @return the representation in bytes of the file content
	 * @throws Exception
	 */
	private byte[] readFileAsBytes(File file) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] fileAsBytes = new byte[(int) file.length()];
		
		// read the whole file into a buffer
		while (fileInputStream.available() != 0) {
			fileInputStream.read(fileAsBytes, 0, fileAsBytes.length);
		}
		fileInputStream.close();
		return fileAsBytes;
	}

	/**
	 * Decrypt encrypted message from file
	 * 
	 * @return an array of bytes representing the clear text
	 */
	public byte[] DecryptMessage() {
		byte[] clearTextBytes = null;
		try {
			PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(
					keyStoreAlias, new KeyStore.PasswordProtection(
							KEY_STORE_PASSWORD.toCharArray()));
			PrivateKey privateKey = keys.getPrivateKey();

			Cipher cipher = Cipher.getInstance(KeyEncryptAlgo,
					KeyEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			SecretKey secretKey = new SecretKeySpec(
					cipher.doFinal(encryptedSecretKey), SecretKeyAlgo);

			cipher = Cipher.getInstance(MessageEncryptAlgo,
					MessageEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

			clearTextBytes = cipher
					.doFinal(readFileAsBytes(new File(encFileLoc)));

		} catch (Exception e) {
			System.out
					.println("Error: Cannot decrypt message " + e.getMessage());
			System.exit(1);
		}
		
		this.decryptedText = clearTextBytes;
		return clearTextBytes;
	}

	/**
	 * This method validates the signature of the decrypted message
	 * 
	 * @return True if signature is valid, false otherwise
	 */
	public Boolean validateSignature() {
		Boolean isValid = false;

		try {

			// Digest message
			MessageDigest messageDigest = MessageDigest.getInstance(DigestAlgo,
					DigestAlgoProvider);
			messageDigest.update(this.decryptedText);
			byte[] clearTextDigest = messageDigest.digest();

			PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(
					keyStoreAlias, new KeyStore.PasswordProtection(
							KEY_STORE_PASSWORD.toCharArray()));
			PublicKey publicKey = entry.getCertificate().getPublicKey();

			// Initiate Signature object
			Signature signatureObj = Signature.getInstance(
					SignatureEncryptAlgo, SignatureEncryptAlgoProvider);
			signatureObj.initVerify(publicKey);

			// Create the signature
			signatureObj.update(clearTextDigest);

			// Save the signature
			isValid = signatureObj.verify(encSignature);
		} catch (Exception e) {
			System.out.println("Error: cannot validate signture "
					+ e.getMessage());
		}

		return isValid;
	}

	/**
	 * This method turns a hex string into a byte array equivalent
	 * @param hexString the string in hex we wish to convert
	 * @return the byte array that represents the hex string
	 */
	public static byte[] hexToByteArray(String hexString) {
		int length = hexString.length();
		byte[] data = new byte[length / 2];
		
		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character
					.digit(hexString.charAt(i + 1), 16));
		}
		
		return data;
	}

	/**
	 * This is the main method to simulate the decryption process
	 */
	public static void main(String[] args) throws Exception {

		System.out.println("Extracting info from the configuration file.");
		Decrypt decryptor = new Decrypt(PATH_TO_CONFIGURATION_FILE);

		System.out.println("The decrypted message:");
		System.out.println(new String(decryptor.DecryptMessage()));
		
		System.out.println("Is this a valid signature? " + decryptor.validateSignature());
	}
}
