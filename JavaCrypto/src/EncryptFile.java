import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

/**
 * This Class encrypts the given file with the AES Algorithm, using the CBC mode
 * and padding.
 * 
 * @author Dominik Hempel & Mickael Soussan
 * 
 */
public class EncryptFile {

	/**
	 * Encrypt given File:
	 * 
	 * @param inputFile
	 * @param OutputFile
	 * @throws CryptoException
	 * @throws ShortBufferException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 */
	@SuppressWarnings("resource")
	public static String encryptFile(String inputFilePath, SecretKey aesKey, byte[] IV)
			throws ShortBufferException, InvalidAlgorithmParameterException,
			NoSuchProviderException {

		// The path to the new Cipher file.
		String cipherFilePath = inputFilePath + ".cipher";

		// The default block size
		final int blockSize = 16;

		try {

			Cipher aesCipher;

			// Create the cipher with AES, mode CBC and padding
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");

			// Initialize the cipher for encryption with Key and IV new
			// IvParameterSpec(IV));
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV));

			// Creates new IO Streams.
			FileInputStream fileInputStream = new FileInputStream(inputFilePath);
			FileOutputStream fos = new FileOutputStream(cipherFilePath);
			CipherOutputStream cos = new CipherOutputStream(fos, aesCipher);

			// Encrypt the file block by block
			byte[] buffer = new byte[blockSize];
			int noBytes = 0;
			byte[] cipherBlock = new byte[aesCipher.getOutputSize(buffer.length)];

			int cipherBytes;
			while ((noBytes = fileInputStream.read(buffer)) != -1) {
				cipherBytes = aesCipher.update(buffer, 0, noBytes, cipherBlock);
				cos.write(cipherBlock, 0, cipherBytes);
			}

			// Call doFinal at end.
			cipherBytes = aesCipher.doFinal(cipherBlock, 0);
			cos.write(cipherBlock, 0, cipherBytes);

			// close the files
			fos.close();
			fos.close();
			cos.close();

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
				| BadPaddingException | IllegalBlockSizeException | IOException ex) {
		}
		return cipherFilePath;
	}
}
