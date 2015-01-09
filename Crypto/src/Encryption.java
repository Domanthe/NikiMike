import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

/**
* A Class that encrypt the plaintext file.
* 
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class Encryption {

	KeyManager keymanager = new KeyManager();
	SignatureHandler sign = new SignatureHandler();
	Path clear = Paths.get("plaintext.txt");
	private Cipher encryptCipher;

	/**
	 * Constructor
	 */
	public Encryption() {
		createIV();
		keymanager.createSecretKey();
		keymanager.loadKeyStore();

		try {
			encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
			encryptCipher.init(Cipher.ENCRYPT_MODE, Globals.cipherKey, new IvParameterSpec(Globals.IV));
		} catch (Exception e) {
			System.out.println("Error: Failed to initiate cipher " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Creates the Random Initialization Vector
	 */
	private void createIV() {
		try {
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			random.nextBytes(Globals.IV);
		} catch (Exception e) {
			System.out.println("Error: Failed to set IV " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Encrypts the given file
	 * 
	 * @param plaintextPath
	 *       
	 */
	public String encryptFile(String plaintextPath) {

		// Saves the name of the encrypted file
		Globals.encryptTextFilePath = plaintextPath + ".encrypted";

		CipherOutputStream cipherOutputStream = null;
		FileInputStream fileInputStream = null;

		try {

			fileInputStream = new FileInputStream(plaintextPath);
			cipherOutputStream = new CipherOutputStream(new FileOutputStream(Globals.encryptTextFilePath), encryptCipher);

			// Encrypts the file block by block
			byte[] blockToEncrypt = new byte[16];
			int ch;
			while ((ch = fileInputStream.read(blockToEncrypt)) != -1) {
				cipherOutputStream.write(blockToEncrypt, 0, ch);
			}

			// Closes streams
			cipherOutputStream.flush();
			cipherOutputStream.close();
			fileInputStream.close();

		} catch (Exception e) {
			System.out.println("Error: cannot encrypt file: " + e.getMessage());
			System.exit(1);
		}

		return Globals.encryptTextFilePath;
	}

	/**
	 * The encryption process main method
	 */
	public static void main(String[] args) {
		Encryption encryptor = new Encryption();
		SignatureHandler sign = new SignatureHandler();
		ConfigurationFile config = new ConfigurationFile();
		KeyManager keymanager = new KeyManager();

		// Signs the file Asymmetrically
		System.out.println("Signs the message.");
		Path path = Paths.get("plaintext.txt");
		sign.SignFile(path);

		// Encrypts our message into a file
		System.out.print("Encrypts the message and save it to a file: ");
		String cipherFileName = encryptor.encryptFile("plaintext.txt");
		System.out.println(cipherFileName);

		// Encrypts the secret key
		System.out.println("Encrypts the secret key.");
		keymanager.encryptSecretKey();

		// Creates the configuration file
		System.out.println("Creates the configuration file for decryption.");
		config.CreateConfigFile("ConfigurationFile.txt");

		System.out.println("Done.");
	}
}
