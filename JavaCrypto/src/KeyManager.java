import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
 * We generate a pair of keys- public and private.
 * we put the public and private key in Key store, "Alice" will send us a key
 * encrypted with our public key, we will decrypt the message with our private key,
 * and encrypt + sign our File (message) with the given (from alice) symmetric key.  
 */

public class KeyManager {

	KeyPairGenerator generateKeyPair;
	SecureRandom secureRandom;
	byte[] seed;
	RSAKeyGenParameterSpec rsaParameterSpec;
	BigInteger publicExponent;
	KeyPair keyPair;
	KeyFactory kfactory;
	RSAPublicKeySpec kspec;
	RSAKeyGenParameterSpec param;

	int e = 128;
	int keysize = 1024; // KeySize

	public KeyManager(String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeySpecException, InvalidAlgorithmParameterException {
		// New Secure Random Number Object
		// secureRandom = new SecureRandom();
		// seed = secureRandom.generateSeed(16);

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
		generateKeyPair.initialize(param);
		// Generates the Key Pair: Public and Private Key.
		keyPair = generateKeyPair.generateKeyPair();

		// or this
		kfactory = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger("12345678", 16),
				new BigInteger("11", 16));
		RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(new BigInteger("12345678", 16),
				new BigInteger("12345678", 16));

		RSAPublicKey pubKey = (RSAPublicKey) kfactory.generatePublic(pubKeySpec);
		RSAPrivateKey privKey = (RSAPrivateKey) kfactory.generatePrivate(privKeySpec);
	}

	// keyPair.initialize(1024, random);

}
