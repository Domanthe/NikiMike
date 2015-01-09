import java.nio.file.Path;
import java.security.KeyStore;
import javax.crypto.SecretKey;

/**
* A Class that contains variables for both encryption and decryption process
* and permits to share between classes.
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class Globals {
	public static KeyStore keyStore = null;
	public static SecretKey cipherKey = null;
	public static byte[] encryptedSecretKey = null;
	public static byte[] signature = null;
	public static byte[] IV = new byte[16];
	public static String encryptTextFilePath = "";
	
	public static String keyStorePath;
	public static String keyStoreAlias;
	public static String encFileLoc;
	public static Path path;
	public static byte[] encSignature;
	public static String MessageEncryptAlgo;
	public static String MessageEncryptAlgoProvider;
	public static String KeyEncryptAlgo;
	public static String KeyEncryptAlgoProvider;
	public static String SignatureEncryptAlgo;
	public static String SignatureEncryptAlgoProvider;
	public static String SecretKeyAlgo;
	public static String DigestAlgo;
	public static String DigestAlgoProvider;
	public static byte[] decryptedText = null;
}
