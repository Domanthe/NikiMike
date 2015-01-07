import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class DecryptFile {

	/**
	 * A Class that decrypts a file.
	 * 
	 * @author Dominik Hempel & Mickael Soussan
	 * 
	 */
	private static final String ALGORITHM = "AES";
	private static final String TRANSFORMATION = "AES";

	/**
	 * Initializes a Decryption Object
	 * 
	 * @param key
	 * @param inputFile
	 * @param outputFile
	 * @throws CryptoException
	 */
	public DecryptFile(String key, File inputFile, File outputFile) {
		doDecryption(Cipher.DECRYPT_MODE, key, inputFile, outputFile);
	}

	private void doDecryption(int cipherMode, String key, File inputFile, File outputFile)
			 {
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
			;
		}
	}
}
