import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;


public class EncryptFile {
	
	/**
	 * Few changes:
	 * 1. Delete param key since we generate one secure with the keygenerator function
	 * 	  so we don't need to send one.
	 * 3. We have to use CipherOutputStream in order to encrypt and create a cipher text not
	 * 	  a CipherInputStream (this will be for the decryption)
	 * 2. The function doesn't need to return a byte[] since inside this same function we use
	 * 	  the outputBytes in order to create a File (encrypted one).		
	 */

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
	 * @param inputFile
	 * @param OutputFile
	 * @throws CryptoException
	 * @throws ShortBufferException
	 * @throws InvalidAlgorithmParameterException 
	 */
	@SuppressWarnings("resource")
	public static void encryptFile(File inputFile, File outputFile)
			throws CryptoException, ShortBufferException, InvalidAlgorithmParameterException {
		
		byte[] outputBytes;
		byte[] IV = null;

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
			
			SecureRandom secureRandom = new SecureRandom();
			
			//Creating IV
			byte[] seed = secureRandom.generateSeed(124);
			AlgorithmParameterSpec algorithmParameterSpecIV = new IvParameterSpec(seed);

			Cipher aesCipher;

			// Create the cipher with AES, mode CBC and padding
			aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			// Initialize the cipher for encryption with Key and IV
			aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, algorithmParameterSpecIV);

			FileInputStream fileInputStream = new FileInputStream(inputFile);

			byte[] inputBytes = new byte[(int) inputFile.length()];
			fileInputStream.read(inputBytes);

			outputBytes = aesCipher.update(inputBytes);

			FileOutputStream fos = new FileOutputStream(outputFile);
			CipherOutputStream cos = new CipherOutputStream(fos, aesCipher);
			
			cos.write(outputBytes);
			
			// fos.write(IV, 0, IV.length);

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
			throw new CryptoException("Error encrypting/decrypting file", ex);
		}
		
	}

}
