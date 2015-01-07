import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Properties;

public class MainEncrypt {

	/**
	 * @param args
	 */
	@SuppressWarnings("static-access")
	public static void main(String[] args) {
		
		/* Path to plain text and Configuration File*/
		final String PATH_TO_PLAIN_TEXT = "D:\\Encrypt\\Message.txt";
		final String PATH_TO_CONFIGURATION_FILE = "D:\\Encrypt\\ConfigurationFile.txt";
		
		MakeSignature sign;
		KeyManager keyManager;

		KeyStore keyStore;
		String alias;
		String password;

		keyManager = new KeyManager();

		// Sign the file Asymmetrically
		System.out.println("Signing message.");
		byte[] signature = new MakeSignature(PATH_TO_PLAIN_TEXT, keyStore, alias, password)
				.getSignature();

		// Encrypt our message into a file
		System.out.print("Encrypt message and put into new cipher file: ");
		String encryptedFilePath = new EncryptFile().encryptFile(PATH_TO_PLAIN_TEXT,
				keyManager.getSecretKey(), keyManager.getIV());
		System.out.println(encryptedFilePath);

		// Encrypt the secret key for later use.
		keyManager.encryptSecretKey();
		System.out.println("Encrypt secret key.");

		// Create the configuration file
		System.out.println("Create the configuration file for decryption.");
		new Config().createConfigurationFile("D:\\Encrypt\\configure.jks", "keystorealias", String configFilePath, byte[] IV,
				String cipherFilePath, byte[] secretKeyBytes, byte[] signature);

		System.out.println("All done :)");

	}
}
