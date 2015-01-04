import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

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

}
