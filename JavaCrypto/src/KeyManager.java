import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;

import javax.crypto.Cipher;

/*
 * Hybrid Encryption: Asymmetric + Symmetric encryption.
 * Generation of pair of keys- public and private.
 * Storing them in Key store, "Alice" sends key encrypted with stored public key (Certificate),
 * Decryption of message with our private key,
 * and encrypt + sign our File (message) with the given (from alice) symmetric key.  
 */
public class KeyManager {
	
	/* Signature algorithm */
	private static final String SIGNATURE_ALGORITHEM = "MD5withRSA";
	private static final String SIGNATURE_ALGORITHEM_PROVIDER = "SunJSSE";

	/* Asymmetric encryption algorithm */
	private static final String ENCRYPT_KEY_ALGORITHEM = "RSA";
	private static final String ENCRYPT_KEY_ALGORITHEM_PROVIDER = "SunJCE";

	/* Message digest algorithm */
	private static final String DIGEST_ALGO = "MD5";
	private static final String DIGEST_ALGO_PROVIDER = "SUN";

	/* Cipher algorithm */
	private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
	private static final String CIPHER_ALGORITHM_PROVIDER = "SunJCE";
	
	/* Key Store */
	private static final String KEY_STORE_ALIAS = "keystorealias";
	private static final String KEY_STORE_PASSWORD = "keystorepassword";
	
	private static final String PATH_TO_KEY_STORE = "C:\\Users\\Tal\\workspace\\JavaCrypto\\keystore.jks";

	
	private KeyStore keyStore;

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

	/*
	 * Initializes a new Key mangaer object.
	 */
	public KeyManager() {

	}

	/**
	 * Generates a new Key Pair using the RSA algorithm, storing it in the
	 * Keystore.
	 */
	public void generateKeyPairRSA() throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException {
		// New Secure Random Number Object
		secureRandom = new SecureRandom();
		seed = secureRandom.generateSeed(16);

		// Generating RSA key pair
		// generateKeyPair = KeyPairGenerator.getInstance("RSA");
		// generateKeyPair.initialize(keysize, secureRandom);

		// For the RSA Algorithm parameters getting a big exponent number
		publicExponent = new BigInteger(Integer.toString(e));
		System.out.println("e =" + publicExponent);

		kfactory = KeyFactory.getInstance("RSA");

		// Initializes RSA keyGenParameters: Key size and the Exponent for the
		// RSA Algorithm
		param = new RSAKeyGenParameterSpec(keysize, publicExponent);
		// Inputs the parameters
		generateKeyPair.initialize(param, secureRandom);
		// Generates the Key Pair: Public and Private Key.
		keyPair = generateKeyPair.generateKeyPair();

		RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();

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
	public void createConfigFile(String configFilePath) {
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

}
