public class Encrypt {

	private static final String ALIAS_KEY_STORE = "keystorealias";
	private static final String PASSWORD_KEY_STORE = "keystorepassword";

	/* Path to plain text and Configuration File */
	final static String PATH_TO_PLAIN_TEXT = "D:\\Encrypt\\Message.txt";
	final static String PATH_TO_CONFIGURATION_FILE = "D:\\Encrypt\\ConfigurationFile.txt";

	/**
	 * @param args
	 * @throws Exception
	 */
	@SuppressWarnings("static-access")
	public static void main(String[] args) throws Exception {

		KeyManager keyManager = new KeyManager();

		// Sign the file Asymmetrically
		System.out.println("Signing message.");
		byte[] signature = new SignatureHandler(PATH_TO_PLAIN_TEXT, keyManager.loadKeyStore(),
				ALIAS_KEY_STORE, PASSWORD_KEY_STORE).getSignature();

		// Encrypt message using AES algorithm, IV, and secret key.
		System.out.print("Encrypt message and put into new cipher file: ");
		String encryptedFilePath = new EncryptFile().encryptFile(PATH_TO_PLAIN_TEXT,
				keyManager.getSecretKey(), keyManager.getIV());
		System.out.println(encryptedFilePath);

		// Encrypt secret key with RSA algorithm.
		byte[] secretKeyBytes = keyManager.encryptSecretKey();
		System.out.println("Encrypt secret key.");

		// Create the configuration file so that later one can decrypt.
		System.out.println("Create the configuration file for decryption.");
		new Config().createConfigFile("D:\\Encrypt\\ConfigurationFile.txt",
				"D:\\Encrypt\\configure.jks", ALIAS_KEY_STORE, keyManager.getIV(),
				encryptedFilePath, secretKeyBytes, signature);

		System.out.println("All done :)");

	}
}
