import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

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

	Config config;

	/**
	 * Initializes a DecryptFile Object.
	 * 
	 * @param key
	 * @param inputFile
	 */
	public DecryptFile(String configFilePath) throws NoSuchAlgorithmException,
			NoSuchProviderException, CertificateException, FileNotFoundException,
			KeyStoreException, IOException {
		// Load data from configuration file.
		config = new Config();
		config.loadConfiguration(configFilePath);
	}

	/**
	 * Decrypts encrypted message from file.
	 * 
	 * @return an array of bytes representing the clear text
	 * @throws Exception
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public byte[] DecryptMessage(KeyStore keyStore, String password)
			throws IllegalBlockSizeException, BadPaddingException, Exception {

		// Gets the private Key from Key Store.
		PrivateKeyEntry keys = (PrivateKeyEntry) keyStore.getEntry(config.getKeyStoreAlias(),
				new KeyStore.PasswordProtection(password.toCharArray()));
		PrivateKey privateKey = keys.getPrivateKey();

		// Initializes Cipher object for decryption of secret key(with loaded
		// algorithm and provider from Configuration File).
		Cipher cipher = Cipher.getInstance(config.getKeyEncryptAlgo(),
				config.getKeyEncryptAlgoProvider());
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		// Gets encrypted Key, and decrypts using the given Algorithm (RSA-
		// initialized by private key before).
		SecretKey secretKey = new SecretKeySpec(cipher.doFinal(config.getCipherSecretKey()),
				config.getSecretKeyAlgo());

		// Initialization of the whole message, using the algorithm and provider
		// from configuration file.
		cipher = Cipher.getInstance(config.getMessageEncryptAlgo(),
				config.getMessageEncryptAlgoProvider());
		cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(config.getIV()));

		return cipher.doFinal(turnToBytes(new File(config.getCipherFilePath())));

	}

	// Represent file as bytes.
	private byte[] turnToBytes(File normalFile) throws Exception {
		FileInputStream fileTurnedToBytes = new FileInputStream(normalFile);
		byte[] fileAsBytes = new byte[(int) normalFile.length()];
		while (fileTurnedToBytes.available() != 0) {
			fileTurnedToBytes.read(fileAsBytes, 0, fileAsBytes.length);
		}
		fileTurnedToBytes.close();
		return fileAsBytes;
	}

}
