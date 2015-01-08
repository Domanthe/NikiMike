import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.spec.InvalidKeySpecException;
import java.security.UnrecoverableEntryException;

/**
 * A Class that makes and verifies signature.
 * 
 * @author Dominik Hempel & Mickael Soussan
 * 
 */
public class SignatureHandler {
	private byte[] textBeforeSignature, signature;
	private static KeyStore keyStore;
	private static String alias;
	private static String password;

	// Initializing MakeSignature.
	@SuppressWarnings("static-access")
	public SignatureHandler(String pathToMessage, KeyStore keyStore, String alias, String password)
			throws Exception {

		this.keyStore = keyStore;
		this.alias = alias;
		this.password = password;
		// Turn file to byte file.
		textBeforeSignature = charFileToByteFile(new File(pathToMessage));

		// Signature operation on byte file.
		initializeSignature(textBeforeSignature);

	}

	/**
	 * return file as bytes array.
	 * 
	 * @param file
	 *            the file that we wish to read from
	 * @return the representation in bytes of the file content
	 * @throws Exception
	 */
	private byte[] charFileToByteFile(File file) throws Exception {
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
	 * @param args
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws KeyStoreException
	 * @throws UnrecoverableEntryException
	 */
	private void initializeSignature(byte[] dataToSign) throws NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, SignatureException,
			UnrecoverableEntryException, KeyStoreException {

		byte[] dataAfterDigest = digestMessage(dataToSign);

		// Get the private key from the KeyStore
		PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias,
				new KeyStore.PasswordProtection(password.toCharArray()));
		PrivateKey privateKey = entry.getPrivateKey();

		Signature signatureInstance = Signature.getInstance("SHA1withDSA");

		// Using the private key, initialize the object.
		signatureInstance.initSign(privateKey);

		// Update and sign the data.
		signatureInstance.update(dataAfterDigest);
		signature = signatureInstance.sign();
	}

	// Gets text with signature.
	public byte[] getSignature() {
		return signature;
	}

	/*
	 * Checking Signature.
	 */
	public static boolean checkSignature(byte[] signature, byte[] data)
			throws NoSuchProviderException, InvalidKeyException, SignatureException,
			InvalidKeySpecException, UnrecoverableEntryException, KeyStoreException,
			NoSuchAlgorithmException {

		byte[] dataAfterDigest = digestMessage(data);

		PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias,
				new KeyStore.PasswordProtection(password.toCharArray()));
		PublicKey publicKey = entry.getCertificate().getPublicKey();

		Signature sig = Signature.getInstance("SHA1withDSA");

		// Initializing the object with the public key.
		sig.initVerify(publicKey);

		// Update and validate the data.
		sig.update(dataAfterDigest);
		boolean isVerified = sig.verify(signature);
		System.out.println("signature verifies: " + isVerified);

		return isVerified;
	}

	// Digest message
	private static byte[] digestMessage(byte[] data) throws NoSuchAlgorithmException,
			NoSuchProviderException {
		MessageDigest messageDigest = MessageDigest.getInstance("MD5", "SUN");
		messageDigest.update(data);
		byte[] clearTextDigest = messageDigest.digest();

		return clearTextDigest;
	}

}
