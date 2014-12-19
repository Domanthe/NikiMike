import java.io.File;

public class SecurityTesting {
	public static void main(String[] args) {
		String key = "Mary has one cat1";
		File inputFile = new File("document.txt");
		File encryptedFile = new File("document.encrypted");
		File decryptedFile = new File("document.decrypted");

		try {
			EncryptFile encrypt = new EncryptFile(key, inputFile, encryptedFile);
			DecryptFile decrypt = new DecryptFile(key, encryptedFile, decryptedFile);
		} catch (CryptoException ex) {
			System.out.println(ex.getMessage());
			ex.printStackTrace();
		}
	}
}
