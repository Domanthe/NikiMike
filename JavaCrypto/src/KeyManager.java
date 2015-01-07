import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/*
 * Hybrid Encryption: Asymmetric + Symmetric encryption.
 * Generation of pair of keys- public and private.
 * Storing them in Key store, "Alice" sends key encrypted with stored public key (Certificate),
 * Decryption of message with our private key,
 * and encrypt + sign our File (message) with the given (from alice) symmetric key.  
 */
public class KeyManager {

	/* Key Store */
	private static final String KEY_STORE_ALIAS = "keystorealias";
	private static final String KEY_STORE_PASSWORD = "keystorepassword";
	private static final String PATH_TO_KEY_STORE = "keystore.jks";

	private KeyStore keyStore;
	private SecretKey secretKey;
	private byte[] secretKeyBytes;
	KeyPairGenerator generateKeyPair;
	SecureRandom secureRandom;
	byte[] seed;
	RSAKeyGenParameterSpec rsaParameterSpec;
	BigInteger publicExponent;
	KeyPair keyPair;
	KeyFactory kfactory;
	RSAPublicKeySpec kspec;
	RSAKeyGenParameterSpec param;
	int e, keysize;
	byte[] IV;

	/*
	 * Initializes a new Key mangaer object.
	 */
	public KeyManager() throws NoSuchAlgorithmException, NoSuchProviderException {

		// Create a Random Secret Key for AES algorithm.
		KeyGenerator keygen = KeyGenerator.getInstance("AES", "SunJCE");
		// Initialize key with size 128 bits.
		keygen.init(128);
		secretKey = keygen.generateKey();

		// Create random IV.
		IV = new byte[16];
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		random.nextBytes(IV);
	}

	// Get IV.
	public byte[] getIV() throws NoSuchAlgorithmException, NoSuchProviderException {
		return IV;
	}

	// Get SecretKey.
	public SecretKey getSecretKey() {
		return secretKey;
	}

	/**
	 * Load Key Store
	 * 
	 * @throws IOException
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 */
	public KeyStore loadKeyStore() throws NoSuchAlgorithmException, CertificateException,
			FileNotFoundException, IOException, KeyStoreException {
		keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(PATH_TO_KEY_STORE), KEY_STORE_PASSWORD.toCharArray());
		return keyStore;
	}

	/**
	 * Encrypt the Secret key
	 * 
	 * @throws KeyStoreException
	 * @throws UnrecoverableEntryException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public byte[] encryptSecretKey() throws NoSuchAlgorithmException, UnrecoverableEntryException,
			KeyStoreException, NoSuchProviderException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		Cipher cipher = null;

		// Get keys from KeyStore.
		PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(KEY_STORE_ALIAS,
				new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
		PublicKey publicKey = keys.getCertificate().getPublicKey();

		// Initiate the cipher
		cipher = Cipher.getInstance("RSA", "SunJCE");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		// Save the encrypted key
		secretKeyBytes = cipher.doFinal(secretKey.getEncoded());
		return secretKeyBytes;

	}

}
