import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.UnrecoverableEntryException;

public class MakeSignature {
	private byte[] textBeforeSignature, signature;
	
	//Initializing MakeSignature.
	public MakeSignature(String pathToMessage, KeyStore keyStore, String alias, String password)
			throws Exception {

		// Turn file to byte file.
		textBeforeSignature = charFileToByteFile(new File(pathToMessage));

		// Signature operation on byte file.
		initializeSignature(textBeforeSignature, keyStore, alias, password);
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
	private void initializeSignature(byte[] dataToSign, KeyStore keyStore, String alias,
			String password) throws NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, SignatureException, UnrecoverableEntryException, KeyStoreException {

		// Get the private key from the KeyStore
		PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias,
				new KeyStore.PasswordProtection(password.toCharArray()));
		PrivateKey privateKey = entry.getPrivateKey();

		Signature signatureInstance = Signature.getInstance("SHA1withDSA");

		// Using the private key, initialize the object.
		signatureInstance.initSign(privateKey);

		// Update and sign the data.
		signatureInstance.update(dataToSign);
		signature = signatureInstance.sign();
	}

	// Gets text with signature.
	public byte[] getSignature() {
		return signature;
	}

}
