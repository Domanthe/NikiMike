import java.io.*;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.util.Properties;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

public class Encrypt {

	/* Constants */
	/* Global path */
	private static final String PATH_TO_PLAIN_TEXT = "C:\\Users\\Tal\\workspace\\JavaCrypto\\Message.txt";
	private static final String PATH_TO_KEY_STORE = "C:\\Users\\Tal\\workspace\\JavaCrypto\\keystore.jks";
	private static final String PATH_TO_CONFIGURATION_FILE = "C:\\Users\\Tal\\workspace\\JavaCrypto\\ConfigurationFile.txt";

	/* Key Store */
	private static final String KEY_STORE_ALIAS = "keystorealias";
	private static final String KEY_STORE_PASSWORD = "keystorepassword";

	/* Cipher algorithm */
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_ALGORITHM_PROVIDER = "SunJCE";

	/* Secure random algorithm (default values) */
	private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
	private static final String SECURE_RANDOM_PROVIDER = "SUN";

	/* Secret Key algorithm */
	private static final String KEY_ALGORITHM = "AES";
	private static final String KEY_ALGORITHM_PROVIDER = "SunJCE";

	/* Asymmetric encryption algorithm */
	private static final String ENCRYPT_KEY_ALGORITHEM = "RSA";
	private static final String ENCRYPT_KEY_ALGORITHEM_PROVIDER = "SunJCE";

	/* Signature algorithm */
	private static final String SIGNATURE_ALGORITHEM = "MD5withRSA";
	private static final String SIGNATURE_ALGORITHEM_PROVIDER = "SunJSSE";

	/* Message digest algorithm */
	private static final String DIGEST_ALGO = "MD5";
	private static final String DIGEST_ALGO_PROVIDER = "SUN";

	private static final char HEX_DIGIT[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'a', 'b', 'c', 'd', 'e', 'f' };

	/* Secret key length. */
	private final static int KEY_LENGTH_BITS = 128;

	/* Block size */
	private final static int BLOCK_SIZE = 16;

	private KeyStore keyStore;
	private SecretKey cipherKey;
	private byte[] cipherSecretKey;
	private Cipher cipher;
	private byte[] IV = new byte[BLOCK_SIZE];
	private String encryptTextFilePath = "";
	private byte[] signature;

	/**
	 * Constructor
	 */
	public Encrypt() {
		// Create the Initialization Vector
		createIV();

		// Create the Secret Key
		createSecretKey();

		// Load KeyStore
		loadKeyStore();

		cipherSecretKey = null;
		signature = null;

		// Initiate Cipher
		try {
			cipher = Cipher.getInstance(CIPHER_ALGORITHM, CIPHER_ALGORITHM_PROVIDER);
			cipher.init(Cipher.ENCRYPT_MODE, cipherKey, new IvParameterSpec(IV));
		} catch (Exception e) {
			System.out.println("Error: Failed to initiate cipher " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Create the Random Initialization Vector
	 */
	private void createIV() {
		try {
			SecureRandom random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM,
					SECURE_RANDOM_PROVIDER);
			random.nextBytes(IV);
		} catch (Exception e) {
			System.out.println("Error: Failed to set IV " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Create the Random Secret Key
	 */
	private void createSecretKey() {
		try {
			KeyGenerator keygen = KeyGenerator.getInstance(KEY_ALGORITHM, KEY_ALGORITHM_PROVIDER);
			keygen.init(KEY_LENGTH_BITS);
			cipherKey = keygen.generateKey();
		} catch (Exception e) {
			System.out.println("Error: Cannot find Algorithem for key generetor " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Load Key Store
	 */
	private void loadKeyStore() {
		try {
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(new FileInputStream(PATH_TO_KEY_STORE), KEY_STORE_PASSWORD.toCharArray());
		} catch (Exception e) {
			System.out.println("Error: Cannot load Key Store " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Read file as bytes
	 * 
	 * @param file
	 *            the file that we wish to read from
	 * @return the representation in bytes of the file content
	 * @throws Exception
	 */
	private byte[] readFileAsBytes(File file) throws Exception {
		FileInputStream fileInputStream = new FileInputStream(file);
		byte[] fileAsBytes = new byte[(int) file.length()];

		// read the whole file into a buffer
		while (fileInputStream.available() != 0) {
			fileInputStream.read(fileAsBytes, 0, fileAsBytes.length);
		}
		fileInputStream.close();
		return fileAsBytes;
	}

	/**
	 * Create the asymmetric digital signature
	 * 
	 * @param cleartextFile
	 *            the path to the clear text file
	 */
	public void SignFile(String cleartextFile) {
		try {

			byte[] clearTextBytes = readFileAsBytes(new File(cleartextFile));

			// Digest message
			// MessageDigest messageDigest = MessageDigest.getInstance(
			// DIGEST_ALGO, DIGEST_ALGO_PROVIDER);
			// messageDigest.update(clearTextBytes);
			// byte[] clearTextDigest = messageDigest.digest();

			// Get the private key from the KeyStore
			PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(KEY_STORE_ALIAS,
					new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
			PrivateKey privateKey = entry.getPrivateKey();

			// Initiate Signature
			Signature signatureObject = Signature.getInstance(SIGNATURE_ALGORITHEM,
					SIGNATURE_ALGORITHEM_PROVIDER);

			// Create the signature
			signatureObject.initSign(privateKey);
			// signatureObject.update(clearTextDigest);
			signature = signatureObject.sign();

		} catch (Exception e) {
			System.out.println("Error: Cannot sign data " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Encrypt the given file
	 * 
	 * @param clearTextFilePath
	 *            the path to the clear text file
	 * @throws Exception
	 */
	public String encryptFile(String clearTextFilePath) {

		// Save the name of the encrypted file
		this.encryptTextFilePath = clearTextFilePath + ".encrypted";

		CipherOutputStream cipherOutputStream = null;
		FileInputStream fileInputStream = null;

		try {

			fileInputStream = new FileInputStream(clearTextFilePath);
			cipherOutputStream = new CipherOutputStream(new FileOutputStream(
					this.encryptTextFilePath), cipher);

			// Encrypt the file block by block
			byte[] blockToEncrypt = new byte[BLOCK_SIZE];
			int ch;
			while ((ch = fileInputStream.read(blockToEncrypt)) != -1) {
				cipherOutputStream.write(blockToEncrypt, 0, ch);
			}

			// Close streams
			cipherOutputStream.flush();
			cipherOutputStream.close();
			fileInputStream.close();

		} catch (Exception e) {
			System.out.println("Error: cannot encrypt file: " + e.getMessage());
			System.exit(1);
		}

		return this.encryptTextFilePath;
	}

	/**
	 * Encrypt the Secret key
	 */
	public void encryptSecretKey() {
		try {
			Cipher cipher = null;

			// Get the keys from the KeyStore
			PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(KEY_STORE_ALIAS,
					new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
			PublicKey publicKey = keys.getCertificate().getPublicKey();

			// Initiate the cipher
			cipher = Cipher.getInstance(ENCRYPT_KEY_ALGORITHEM, ENCRYPT_KEY_ALGORITHEM_PROVIDER);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);

			// Save the encrypted key
			cipherSecretKey = cipher.doFinal(cipherKey.getEncoded());
		} catch (Exception e) {
			System.out.println("Error: cannot encrypt key " + e.getMessage());
			System.exit(1);
		}
	}

	/**
	 * Create configuration file. This file holds the information in order to
	 * decrypt the file.
	 * 
	 * @param configFilePath
	 *            the path to the configuration file
	 */
	public void CreateConfigFile(String configFilePath) {
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(configFilePath);

			Properties configFile = new Properties();
			configFile.setProperty("KeyStoreFile", PATH_TO_KEY_STORE);
			configFile.setProperty("KeyStoreAlias", KEY_STORE_ALIAS);
			configFile.setProperty("IV", toHex(IV));
			configFile.setProperty("EncryptedFileLocation", this.encryptTextFilePath);
			configFile.setProperty("EncryptedKey", toHex(cipherSecretKey));
			configFile.setProperty("Signature", toHex(signature));
			configFile.setProperty("MessageEncryptAlgo", CIPHER_ALGORITHM);
			configFile.setProperty("MessageEncryptAlgoProvider", CIPHER_ALGORITHM_PROVIDER);
			configFile.setProperty("KeyEncryptAlgo", ENCRYPT_KEY_ALGORITHEM);
			configFile.setProperty("KeyEncryptAlgoProvider", ENCRYPT_KEY_ALGORITHEM_PROVIDER);
			configFile.setProperty("SignatureEncryptAlgo", SIGNATURE_ALGORITHEM);
			configFile.setProperty("SignatureEncryptAlgoProvider", SIGNATURE_ALGORITHEM_PROVIDER);
			configFile.setProperty("SecretKeyAlgo", KEY_ALGORITHM);
			configFile.setProperty("DigestAlgo", DIGEST_ALGO);
			configFile.setProperty("DigestAlgoProvider", DIGEST_ALGO_PROVIDER);

			configFile.store(fileOutputStream, null);
		} catch (Exception e) {
			System.out.println("Error: cannot create the configuration file " + e.getMessage());
			System.exit(1);
		}
	}

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
		char[] hex = { HEX_DIGIT[(b >> 4) & 0x0f], HEX_DIGIT[b & 0x0f] };
		return new String(hex);
	}

	/**
	 * This is the main method to simulate the encryption process
	 */
	public static void main(String[] args) {

		// Create the encrypt object
		Encrypt encryptor = new Encrypt();

		// Sign the file Asymmetrically
		System.out.println("Signing the message (Asymmetrical digital signture). ");
		encryptor.SignFile(PATH_TO_PLAIN_TEXT);

		// Encrypt our message into a file
		System.out.print("Encrypt the message and save it to a file: ");
		String cipherFileName = encryptor.encryptFile(PATH_TO_PLAIN_TEXT);
		System.out.println(cipherFileName);

		// Encrypt the key
		System.out.println("Encrypt the secret key.");
		encryptor.encryptSecretKey();

		// Create the configuration file
		System.out.println("Create the configuration file for decryption.");
		encryptor.CreateConfigFile(PATH_TO_CONFIGURATION_FILE);

		System.out.println("All done :)");
	}
}
