import java.io.FileOutputStream;
import java.io.FileReader;
import java.nio.file.Paths;
import java.util.Properties;


/**
* A Class that manage everything concerning the configuration file
* It creates it and extracts from it the different informations
* 
*
* @author Dominik Hempel & Mickael Soussan
* @id	- 328944921
*/
public class ConfigurationFile {
	/**
	 * Creates configuration file.
	 * 
	 * @param configFilePath
	 *  
	 */
	public void CreateConfigFile(String configFilePath) {
		try {
			FileOutputStream fileOutputStream = new FileOutputStream(configFilePath);

			Properties configFile = new Properties();
			configFile.setProperty("KeyStoreFile", "keystore.jks");
			configFile.setProperty("KeyStoreAlias", "domain");
			configFile.setProperty("IV", bytesToHex(Globals.IV));
			configFile.setProperty("EncryptedFileLocation", Globals.encryptTextFilePath);
			configFile.setProperty("EncryptedKey", bytesToHex(Globals.encryptedSecretKey));
			configFile.setProperty("Signature", bytesToHex(Globals.signature));
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
	
	/**
	 * Converts from byte array to hex string
	 */
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	/**
	 * Extracts parameters from configuration file
	 * 
	 * @param configFilePath
	 *        
	 */
	public void extractConfiguration(String configFilePath) {
		Properties fileOutputStream = new Properties();
		try {
			fileOutputStream.load(new FileReader(configFilePath));

			Globals.keyStorePath = fileOutputStream.getProperty("KeyStoreFile");
			Globals.keyStoreAlias = fileOutputStream.getProperty("KeyStoreAlias");
			Globals.IV = hexStringToByteArray(fileOutputStream.getProperty("IV"));	
			Globals.encFileLoc = fileOutputStream.getProperty("EncryptedFileLocation");
			Globals.path = Paths.get(Globals.encFileLoc);
			Globals.encryptedSecretKey = hexStringToByteArray(fileOutputStream.getProperty("EncryptedKey"));
			Globals.encSignature = hexStringToByteArray(fileOutputStream.getProperty("Signature"));
			Globals.MessageEncryptAlgo = fileOutputStream.getProperty("MessageEncryptAlgo");
			Globals.MessageEncryptAlgoProvider = fileOutputStream.getProperty("MessageEncryptAlgoProvider");
			Globals.KeyEncryptAlgo = fileOutputStream.getProperty("KeyEncryptAlgo");
			Globals.KeyEncryptAlgoProvider = fileOutputStream.getProperty("KeyEncryptAlgoProvider");
			Globals.SignatureEncryptAlgo = fileOutputStream.getProperty("SignatureEncryptAlgo");
			Globals.SignatureEncryptAlgoProvider = fileOutputStream.getProperty("SignatureEncryptAlgoProvider");
			Globals.SecretKeyAlgo = fileOutputStream.getProperty("SecretKeyAlgo");
			Globals.DigestAlgo = fileOutputStream.getProperty("DigestAlgo");
			Globals.DigestAlgoProvider = fileOutputStream.getProperty("DigestAlgoProvider");
			
		} catch (Exception e) {
			System.out.println("Error: cannot read the configuration file " + e.getMessage());
			System.exit(1);
		}
	}
	
	/**
	 * Converts a hex string into a byte array
	 * @param s the string in hex
	 * @return b the byte[], conversion of s
	 */
	public static byte[] hexStringToByteArray(String s) {
	    byte[] b = new byte[s.length() / 2];
	    for (int i = 0; i < b.length; i++) {
	      int index = i * 2;
	      int v = Integer.parseInt(s.substring(index, index + 2), 16);
	      b[i] = (byte) v;
	    }
	    return b;
	}
	
}
