import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class verifySignature {

	public static boolean checkSignature(byte[] signature, byte[] data, byte[] encodedPubKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
			SignatureException, InvalidKeySpecException {

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedPubKey);

		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

		Signature sig = Signature.getInstance("SHA1withDSA");

		// Initializing the object with the public key.
		sig.initVerify(pubKey);

		// Update and sign the data.
		sig.update(data);
		boolean verifies = sig.verify(signature);
		System.out.println("signature verifies: " + verifies);

		return verifies;
	}
}
