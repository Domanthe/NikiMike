
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyStore.PrivateKeyEntry;

/**
* A Class that creates and verifies the digital signature.
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class SignatureHandler {
	
	
	/**
	 * Creates the asymmetric digital signature
	 * 
	 * @param cleartextFile
	 * 
	 */
	public void SignFile(Path cleartextFile) {
		
		try {

			byte[] clearTextBytes = Files.readAllBytes(cleartextFile);

			// Digest message
			MessageDigest messageDigest = MessageDigest.getInstance("MD5", "SUN");
			messageDigest.update(clearTextBytes);
			byte[] clearTextDigest = messageDigest.digest();

			// Get the private key from the KeyStore
			PrivateKeyEntry entry = (PrivateKeyEntry) Globals.keyStore.getEntry("domain", new KeyStore.PasswordProtection("NikiMike".toCharArray()));
			PrivateKey privateKey = entry.getPrivateKey();

			// Initiate Signature
			Signature signatureObject = Signature.getInstance("MD5withRSA", "SunJSSE");

			// Create the signature
			signatureObject.initSign(privateKey);
			signatureObject.update(clearTextDigest);
			Globals.signature = signatureObject.sign();

		} catch (Exception e) {
			System.out.println("Error: Cannot sign data " + e.getMessage());
			System.exit(1);
		}
		
	}
	
	/**
	 * Checks for valid signature
	 * 
	 * @return true if valid, false otherwise
	 */
	public Boolean validateSignature() {
		Boolean isValid = false;

		try {

			// Digest message
			MessageDigest messageDigest = MessageDigest.getInstance(Globals.DigestAlgo, Globals.DigestAlgoProvider);
			messageDigest.update(Globals.decryptedText);
			byte[] clearTextDigest = messageDigest.digest();

			PrivateKeyEntry entry = (PrivateKeyEntry) Globals.keyStore.getEntry(Globals.keyStoreAlias, new KeyStore.PasswordProtection("NikiMike".toCharArray()));
			PublicKey publicKey = entry.getCertificate().getPublicKey();

			// Initiates Signature object
			Signature signatureObj = Signature.getInstance(Globals.SignatureEncryptAlgo, Globals.SignatureEncryptAlgoProvider);
			signatureObj.initVerify(publicKey);

			// Creates the signature
			signatureObj.update(clearTextDigest);

			// Saves the signature
			isValid = signatureObj.verify(Globals.encSignature);
		} catch (Exception e) {
			System.out.println("Error: cannot validate signture " + e.getMessage());
		}

		return isValid;
	}

}
