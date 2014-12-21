import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

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
	 * Encrypt given File:
	 * 
	 * @param key
	 * @param inputFile
	 * @param outputFile
	 * @throws CryptoException
	 * @throws ShortBufferException 
	 */
	public static byte[] encryptFile(String key, File inputFile, File outputFile)
			throws CryptoException, ShortBufferException {
		byte[] outputBytes;
		byte[] IV = null;
		FileInputStream fileInputStream;
		FileOutputStream fos;
		CipherInputStream cipherInputStream;
		// The default block size
		final int blockSize = 16;

		try {

			// Instantiate a KeyGenerator for AES. We do not specify a provider,
			// because we do not care about a particular AES key generation
			// implementation. Since we do not initialize the KeyGenerator, a
			// system-provided source of randomness and a default keysize will
			// be used to create the AES key:
			KeyGenerator keygen = KeyGenerator.getInstance("AES");
			SecretKey aesKey = keygen.generateKey();

			Cipher aesCipher;

			// Create the cipher
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			// Initialize the cipher for encryption
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

			// 3. create the IV
			AlgorithmParameterSpec IVspec = new IvParameterSpec(IV);

			fileInputStream = new FileInputStream(inputFile);
			cipherInputStream = new CipherInputStream(fileInputStream, aesCipher);

			byte[] inputBytes = new byte[(int) inputFile.length()];
			fileInputStream.read(inputBytes);

			outputBytes = aesCipher.update(inputBytes);

			FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
			fileOutputStream.write(outputBytes);

			// fos.write(IV, 0, IV.length);

			byte[] buffer = new byte[blockSize];
			int noBytes = 0;
			byte[] cipherBlock = new byte[aesCipher.getOutputSize(buffer.length)];
			int cipherBytes;
			while ((noBytes = fileInputStream.read(buffer)) != -1) {
				cipherBytes = aesCipher.update(buffer, 0, noBytes, cipherBlock);
				fileOutputStream.write(cipherBlock, 0, cipherBytes);
			}
			//Call doFinal at end.
			cipherBytes = aesCipher.doFinal(cipherBlock, 0);
			fileOutputStream.write(cipherBlock, 0, cipherBytes);

			// close the files
			fileOutputStream.close();
			fileInputStream.close();

			// // Our cleartext
			// byte[] cleartext = "This is just an example".getBytes();
			//
			// // Encrypt the cleartext
			// byte[] ciphertext = aesCipher.doFinal(cleartext);
			//
			// // Initialize the same cipher for decryption
			// aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
			//
			// // Decrypt the ciphertext
			// byte[] cleartext1 = aesCipher.doFinal(ciphertext);

			// Key secretKey = new SecretKeySpec(key.getBytes(), ALGORITHM);
			// Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			// cipher.init(cipherMode, secretKey);
			//
			// FileInputStream inputStream = new FileInputStream(inputFile);
			// byte[] inputBytes = new byte[(int) inputFile.length()];
			// inputStream.read(inputBytes);
			//
			// outputBytes = cipher.doFinal(inputBytes);
			//
			// FileOutputStream outputStream = new FileOutputStream(outputFile);
			// outputStream.write(outputBytes);
			//
			// inputStream.close();
			// outputStream.close();

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
				| BadPaddingException | IllegalBlockSizeException | IOException ex) {
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
		return outputBytes;
	}

}
