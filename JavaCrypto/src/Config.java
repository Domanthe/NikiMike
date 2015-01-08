import java.io.FileOutputStream;
import java.io.FileReader;
import java.util.Properties;

public class Config {

	/* Message digest algorithm */
	private static final String DIGEST_ALGO = "MD5";
	private static final String DIGEST_ALGO_PROVIDER = "SUN";
	final static String PATH_TO_CONFIGURATION_FILE = "D:\\Encrypt\\ConfigurationFile.txt";

	private String keyStorePath;
	private String keyStoreAlias;
	private byte[] IV = new byte[16];
	private String cipherFilePath;
	private byte[] cipherSecretKey;
	private byte[] cipherSignature;
	private String MessageEncryptAlgo;
	private String MessageEncryptAlgoProvider;
	private String KeyEncryptAlgo;
	private String KeyEncryptAlgoProvider;
	private String SignatureEncryptAlgo;
	private String SignatureEncryptAlgoProvider;
	private String SecretKeyAlgo;
	private String DigestAlgo;
	private String DigestAlgoProvider;

	// Converts from array of bytes to Hex represantation.
	public static String toHex(byte[] bytes) {
		if (bytes == null) {
			return null;
		}
		StringBuilder buffer = new StringBuilder(bytes.length * 2);
		for (byte thisByte : bytes) {
			buffer.append(byteToHex(thisByte));
		}
		return buffer.toString();
	}

	// Converts to Bytearray.
	public static byte[] hexToByteArray(String hexString) {
		int length = hexString.length();
		byte[] data = new byte[length / 2];

		for (int i = 0; i < length; i += 2) {
			data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character
					.digit(hexString.charAt(i + 1), 16));
		}
		return data;
	}

	// Converts from 1 Byte to Hex.
	private static String byteToHex(byte b) {
		char HEX_DIGIT[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
				'e', 'f' };
		char[] hex = { HEX_DIGIT[(b >> 4) & 0x0f], HEX_DIGIT[b & 0x0f] };
		return new String(hex);
	}

	/**
	 * Creates Configuration File. THe File holds the information in order to
	 * decrypt the file.
	 * 
	 * @param configFilePath
	 *            the path to the configuration file
	 */
	public void createConfigFile(String configFilePath, String pathToKS, String aliasKS, byte[] IV,
			String cipherFilePath, byte[] secretKeyBytes, byte[] signature) {
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(configFilePath);

			Properties configFile = new Properties();
			configFile.setProperty("KeyStoreFile", pathToKS);
			configFile.setProperty("KeyStoreAlias", aliasKS);
			configFile.setProperty("IV", toHex(IV));
			configFile.setProperty("EncryptedFileLocation", cipherFilePath);
			configFile.setProperty("EncryptedKey", toHex(secretKeyBytes));
			configFile.setProperty("Signature", toHex(signature));
			configFile.setProperty("MessageEncryptAlgo", "AES/CBC/PKCS5Padding");
			configFile.setProperty("MessageEncryptAlgoProvider", "SunJCE");
			configFile.setProperty("KeyEncryptAlgo", "RSA");
			configFile.setProperty("KeyEncryptAlgoProvider", "SunJCE");
			configFile.setProperty("SignatureEncryptAlgo", "MD5withRSA");
			configFile.setProperty("SignatureEncryptAlgoProvider", "SunJSSE");
			configFile.setProperty("SecretKeyAlgo", "AES");
			configFile.setProperty("DigestAlgo", DIGEST_ALGO);
			configFile.setProperty("DigestAlgoProvider", DIGEST_ALGO_PROVIDER);

			configFile.store(fileOutputStream, null);
		} catch (Exception e) {
			System.out.println("Error: cannot create the configuration file " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Loads all info needed from configuration file for decryption.
	 * 
	 * @param configFilePath
	 *            - Configuration file location
	 */
	public void loadConfiguration(String configFilePath) {
		Properties fileOutputStream = new Properties();
		try {
			fileOutputStream.load(new FileReader(configFilePath));

			keyStorePath = fileOutputStream.getProperty("KeyStoreFile");
			keyStoreAlias = fileOutputStream.getProperty("KeyStoreAlias");
			IV = hexToByteArray(fileOutputStream.getProperty("IV"));
			cipherFilePath = fileOutputStream.getProperty("EncryptedFileLocation");
			cipherSecretKey = hexToByteArray(fileOutputStream.getProperty("EncryptedKey"));
			cipherSignature = hexToByteArray(fileOutputStream.getProperty("Signature"));
			MessageEncryptAlgo = fileOutputStream.getProperty("MessageEncryptAlgo");
			MessageEncryptAlgoProvider = fileOutputStream.getProperty("MessageEncryptAlgoProvider");
			KeyEncryptAlgo = fileOutputStream.getProperty("KeyEncryptAlgo");
			KeyEncryptAlgoProvider = fileOutputStream.getProperty("KeyEncryptAlgoProvider");
			SignatureEncryptAlgo = fileOutputStream.getProperty("SignatureEncryptAlgo");
			SignatureEncryptAlgoProvider = fileOutputStream
					.getProperty("SignatureEncryptAlgoProvider");
			SecretKeyAlgo = fileOutputStream.getProperty("SecretKeyAlgo");
			DigestAlgo = fileOutputStream.getProperty("DigestAlgo");
			DigestAlgoProvider = fileOutputStream.getProperty("DigestAlgoProvider");
		} catch (Exception e) {
			System.out.println("Error: cannot read the configuration file " + e.getMessage());
			System.exit(1);
		}

	}

	/*
	 * Getters: so one can get all info he needs for Decryption.
	 */

	public String getKeyStorePath() {
		return keyStoreAlias;
	}

	public String getKeyStoreAlias() {
		return keyStorePath;
	}

	public byte[] getIV() {
		return IV;
	}

	public String getCipherFilePath() {
		return cipherFilePath;
	}

	public byte[] getCipherSecretKey() {
		return cipherSecretKey;
	}

	public byte[] getCipherSignature() {
		return cipherSignature;
	}

	public String getMessageEncryptAlgo() {
		return MessageEncryptAlgo;
	}

	public String getMessageEncryptAlgoProvider() {
		return MessageEncryptAlgoProvider;
	}

	public String getKeyEncryptAlgo() {
		return KeyEncryptAlgo;
	}

	public String getKeyEncryptAlgoProvider() {
		return KeyEncryptAlgoProvider;
	}

	public String getSignatureEncryptAlgo() {
		return SignatureEncryptAlgo;
	}

	public String getSignatureEncryptAlgoProvider() {
		return SignatureEncryptAlgoProvider;
	}

	public String getSecretKeyAlgo() {
		return SecretKeyAlgo;
	}

	public String getDigestAlgo() {
		return DigestAlgo;
	}

	public String getDigestAlgoProvider() {
		return DigestAlgoProvider;
	}

	public String getConfigPath() {
		return PATH_TO_CONFIGURATION_FILE;
	}

}
