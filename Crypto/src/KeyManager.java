import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.KeyStore.PrivateKeyEntry;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;


/**
* A Class that manage everything concerning the keys.
* 
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class KeyManager {
	
	/**
	 * Creates the Random Secret Key
	 */
	public void createSecretKey() {
		
		try {
			KeyGenerator keygen = KeyGenerator.getInstance("AES", "SunJCE");
			keygen.init(128);
			Globals.cipherKey = keygen.generateKey();
		} catch (Exception e) {
			System.out.println("Error: Cannot find Algorithm for key generetor " + e.getMessage());
			System.exit(1);
		}
		
	}
	
	/**
	 * Loads Key Store
	 */
	public void loadKeyStore() {
		try {
			Globals.keyStore = KeyStore.getInstance("JKS");
			Globals.keyStore.load(new FileInputStream("keystore.jks"), "keystorepassword".toCharArray());
		} catch (Exception e) {
			System.out.println("Error: Cannot load Key Store " + e.getMessage());
			System.exit(1);
		}
		
	}
	
	/**
	 * Encrypts the Secret key
	 */
	public void encryptSecretKey() {
		try {
			Cipher cipher = null;

			// Get the keys from the KeyStore
			PrivateKeyEntry keys = (PrivateKeyEntry) Globals.keyStore.getEntry("keystorealias", new KeyStore.PasswordProtection("keystorepassword".toCharArray()));
			PublicKey publicKey = keys.getCertificate().getPublicKey();

			// Initiate the cipher
			cipher = Cipher.getInstance("RSA", "SunJCE");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			// Save the encrypted key
			Globals.encryptedSecretKey = cipher.doFinal(Globals.cipherKey.getEncoded());
		} catch (Exception e) {
			System.out.println("Error: cannot encrypt key " + e.getMessage());
			System.exit(1);
		}
	}

}
