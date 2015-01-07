import java.io.FileOutputStream;
import java.util.Properties;

public class Config {

	/* Message digest algorithm */
	private static final String DIGEST_ALGO = "MD5";
	private static final String DIGEST_ALGO_PROVIDER = "SUN";

	/**
	 * Convert a byte array into its hex String equivalent.
	 * 
	 * @param bytes
	 *            an array of bytes to be converted to hex
	 * @return the hex representation of the byte array
	 * 
	 */
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

	/**
	 * Convert a single byte into its hex String equivalent.
	 * 
	 * @param b
	 *            a byte to be converted
	 * @return a converted byte to its hex equivalent
	 */
	private static String byteToHex(byte b) {
		char HEX_DIGIT[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
				'e', 'f' };
		char[] hex = { HEX_DIGIT[(b >> 4) & 0x0f], HEX_DIGIT[b & 0x0f] };
		return new String(hex);
	}

	/**
	 * Create configuration file. This file holds the information in order to
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
}
