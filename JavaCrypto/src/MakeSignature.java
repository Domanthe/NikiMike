import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

public class MakeSignature {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException 
	 * @throws SignatureException 
	 */
	public static byte[] initializeSignature(byte[] data) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException {

		// Get a key pair generator object for generating keys for the DSA
		// algorithm.
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");

		// Use Algorithm-Independent Initialization, a SecureRandom
		// implementation of the highest-priority installed provider will be
		// used. Generate keys with a keysize of 1024.
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(1024, random);

		// Generating the key pair.
		KeyPair pair = keyGen.generateKeyPair();

		Signature dsa = Signature.getInstance("SHA1withDSA");

		// Using the key pair, initialize
		// the object with the private key. 
		PrivateKey priv = pair.getPrivate();
		dsa.initSign(priv);

		// Update and sign the data.
		dsa.update(data);
		byte[] signature = dsa.sign();
		return signature;
	}

}
