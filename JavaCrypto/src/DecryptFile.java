import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.KeyStore.PrivateKeyEntry;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
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
	KeyManager km;

	/**
	 * Initializes a Decryption Object
	 * 
	 * @param key
	 * @param inputFile
	 * @param outputFile
	 * @throws CryptoException
	 */
	public DecryptFile(String configurationFile) {
		// Extract parameters from file
		extractConfiguration("ConfigurationFile.txt");

		// Load Key store
		km.loadKeyStore();
	}
	
	/**
	 * Read file as bytes
	 * 
	 * @param file
	 *            the file we are reading from
	 * @return the representation in bytes of the file content
	 * @throws Exception
	 */
	private byte[] readFileAsBytes(File file) throws Exception {
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
	 * Decrypt encrypted message from file
	 * 
	 * @return an array of bytes representing the clear text
	 */
	public byte[] DecryptMessage() {
		byte[] clearTextBytes = null;
		try {
			PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(ksAlias,
					new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
			PrivateKey privateKey = keys.getPrivateKey();

			Cipher cipher = Cipher.getInstance(KeyEncryptAlgo, KeyEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			SecretKey secretKey = new SecretKeySpec(cipher.doFinal(cipherSecretKey), SecretKeyAlgo);

			cipher = Cipher.getInstance(MessageEncryptAlgo, MessageEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

			clearTextBytes = cipher.doFinal(readFileAsBytes(new File(cipherFileLocation)));

		} catch (Exception e) {
			System.out.println("Error: Cannot decrypt message " + e.getMessage());
			System.exit(1);
		}

		this.decryptedText = clearTextBytes;
		return clearTextBytes;
	}
	
	/**
	 * Decrypt encrypted message from file
	 * 
	 * @return an array of bytes representing the clear text
	 */
	public byte[] DecryptMessage() {
		byte[] clearTextBytes = null;
		try {
			PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(ksAlias,
					new KeyStore.PasswordProtection(KEY_STORE_PASSWORD.toCharArray()));
			PrivateKey privateKey = keys.getPrivateKey();

			Cipher cipher = Cipher.getInstance(KeyEncryptAlgo, KeyEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			SecretKey secretKey = new SecretKeySpec(cipher.doFinal(cipherSecretKey),
					SecretKeyAlgo);

			cipher = Cipher.getInstance(MessageEncryptAlgo, MessageEncryptAlgoProvider);
			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));

			clearTextBytes = cipher.doFinal(readFileAsBytes(new File(cipherFileLocation)));

		} catch (Exception e) {
			System.out.println("Error: Cannot decrypt message " + e.getMessage());
			System.exit(1);
		}

		this.decryptedText = clearTextBytes;
		return clearTextBytes;
	}


}
