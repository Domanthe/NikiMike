import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class Decrypt {

	final static String PATH_TO_CONFIGURATION_FILE = "D:\\Encrypt\\ConfigurationFile.txt";
	private static final String KEY_STORE_PASSWORD = "easiestpasswordeveronplanet";

	/**
	 * @param args
	 * @throws Exception
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	@SuppressWarnings("static-access")
	public static void main(String[] args) throws IllegalBlockSizeException, BadPaddingException,
			CertificateException, FileNotFoundException, IOException, Exception {

		Config config = new Config();
		config.loadConfiguration(PATH_TO_CONFIGURATION_FILE);
		KeyManager keyManager = new KeyManager();

		System.out.println("Loading data from configuration file.");
		DecryptFile decryptMessage = new DecryptFile(config);

		System.out.println("The decrypted message:");
		System.out.println(new String(decryptMessage.decrypt(keyManager.loadKeyStore(),
				KEY_STORE_PASSWORD)));
		byte[] decryptedMessage = decryptMessage.decrypt(keyManager.loadKeyStore(),
				KEY_STORE_PASSWORD);

		SignatureHandler validateSignature = new SignatureHandler("", keyManager.loadKeyStore(),
				config.getKeyStoreAlias(), KEY_STORE_PASSWORD);
		System.out.println("Is this a valid signature? "
				+ validateSignature.checkSignature(config.getCipherSignature(), decryptedMessage));
	}
}
