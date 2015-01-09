import java.nio.file.Files;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
* A Class that encrypt the plaintext file.
* 
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class Decryption {
	
	KeyManager keymanager = new KeyManager();
	ConfigurationFile config = new ConfigurationFile();

	/**
	 * Constructor
	 * 
	 * @param configFileLocation
	 *      
	 */
	public Decryption(String configFileLocation) {

		// Extract parameters from file
		config.extractConfiguration(configFileLocation);

		// Load Key store
		keymanager.loadKeyStore();
	}

	/**
	 * Decrypts encrypted message from file
	 * 
	 * @return an array of bytes representing the clear text
	 */
	public byte[] DecryptMessage() {
		byte[] clearTextBytes = null;
		try {
			PrivateKeyEntry keys = (PrivateKeyEntry) Globals.keyStore.getEntry(Globals.keyStoreAlias, new KeyStore.PasswordProtection("NikiMike".toCharArray()));
			PrivateKey privateKey = keys.getPrivateKey();

			Cipher cipher = Cipher.getInstance(Globals.KeyEncryptAlgo, Globals.KeyEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			SecretKey secretKey = new SecretKeySpec(cipher.doFinal(Globals.encryptedSecretKey), Globals.SecretKeyAlgo);

			cipher = Cipher.getInstance(Globals.MessageEncryptAlgo, Globals.MessageEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(Globals.IV));

			clearTextBytes = cipher.doFinal(Files.readAllBytes(Globals.path));

		} catch (Exception e) {
			System.out
					.println("Error: Cannot decrypt message " + e.getMessage());
			System.exit(1);
		}
		
		Globals.decryptedText = clearTextBytes;
		return clearTextBytes;
	}

	/**
	 * The decryption process main method
	 */
	public static void main(String[] args) throws Exception {
		SignatureHandler sign = new SignatureHandler();

		System.out.println("Extracting info from the configuration file.");
		Decryption decryptor = new Decryption("ConfigurationFile.txt");

		System.out.println("The decrypted message:");
		System.out.println(new String(decryptor.DecryptMessage()));
		
		System.out.println("Is this a valid signature? " + sign.validateSignature());
	}
}
