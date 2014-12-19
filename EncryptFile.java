import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class EncryptFile {

	/**
	 * A Class that encrypts a file.
	 * 
	 * @author Dominik Hempel & Mickael Soussan
	 * 
	 */
	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES";

	/**
	 * Initializes an Encryption Object with:
	 * 
	 * @param key
	 * @param inputFile
	 * @param outputFile
	 * @throws CryptoException
	 */
	public EncryptFile(String key, File inputFile, File outputFile) throws CryptoException {
		doEncryption(Cipher.ENCRYPT_MODE, key, inputFile, outputFile);
	}

	private void doEncryption(int cipherMode, String key, File inputFile, File outputFile)
			throws CryptoException {
		try {
			Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(cipherMode, secretKey);

			FileInputStream inputStream = new FileInputStream(inputFile);
			byte[] inputBytes = new byte[(int) inputFile.length()];
			inputStream.read(inputBytes);

			byte[] outputBytes = cipher.doFinal(inputBytes);

			FileOutputStream outputStream = new FileOutputStream(outputFile);
			outputStream.write(outputBytes);

			inputStream.close();
			outputStream.close();

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
				| BadPaddingException | IllegalBlockSizeException | IOException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
	}

}
