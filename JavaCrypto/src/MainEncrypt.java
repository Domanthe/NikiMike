import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.util.Properties;

public class MainEncrypt {

	/* Global path */
	private static final String PATH_TO_PLAIN_TEXT = "D:\\Encrypt\\Message.txt";
	private static final String PATH_TO_CONFIGURATION_FILE = "D:\\Encrypt\\ConfigurationFile.txt";

	/**
	 * @param args
	 */
	public static void main(String[] args) {

		MakeSignature sign;
		KeyStore keyStore;
		String alias;
		String password;

		// Sign the file Asymmetrically
		System.out.println("Signing message.");
		byte[] signature = new MakeSignature(PATH_TO_PLAIN_TEXT, keyStore, alias, password)
				.getSignature();

		// Encrypt our message into a file
		System.out.print("Encrypt message and put into new cipher file: ");
		String cipherFileName = new EncryptFile().encryptFile(PATH_TO_PLAIN_TEXT);
		System.out.println(cipherFileName);

		// Encrypt the key
		System.out.println("Encrypt the secret key.");
		new KeyManager().encryptSecretKey();

		// Create the configuration file
		System.out.println("Create the configuration file for decryption.");
		new KeyManager.createConfigurationFile(PATH_TO_CONFIGURATION_FILE);

		System.out.println("All done :)");

	}

}
