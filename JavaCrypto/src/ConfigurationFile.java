import java.io.FileOutputStream;
import java.util.Properties;


public class ConfigurationFile {
	/**
	 * Create configuration file. This file holds the information in order to
	 * decrypt the file.
	 * 
	 * @param configFilePath
	 *            the path to the configuration file
	 */
	public void CreateConfigFile(String configFilePath) {
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(configFilePath);

			Properties configFile = new Properties();
			configFile.setProperty("KeyStoreFile", "keystore.jks");
			configFile.setProperty("KeyStoreAlias", "NikiMike");
			configFile.setProperty("IV", toHex(IV));
			configFile.setProperty("EncryptedFileLocation", this.encryptTextFilePath);
			configFile.setProperty("EncryptedKey", toHex(cipherSecretKey));
			configFile.setProperty("Signature", toHex(signature));
			configFile.setProperty("MessageEncryptAlgo", "AES/CBC/PKCS5Padding");
			configFile.setProperty("MessageEncryptAlgoProvider", "SunJCE");
			configFile.setProperty("KeyEncryptAlgo", "RSA");
			configFile.setProperty("KeyEncryptAlgoProvider", "SunJCE");
			configFile.setProperty("SignatureEncryptAlgo", "MD5withRSA");
			configFile.setProperty("SignatureEncryptAlgoProvider", "SunJSSE");
			configFile.setProperty("SecretKeyAlgo", "AES");
			configFile.setProperty("DigestAlgo", "MD5");
			configFile.setProperty("DigestAlgoProvider", "SUN");

			configFile.store(fileOutputStream, null);
		} catch (Exception e) {
			System.out.println("Error: cannot create the configuration file " + e.getMessage());
			System.exit(1);
		}
	}
}
