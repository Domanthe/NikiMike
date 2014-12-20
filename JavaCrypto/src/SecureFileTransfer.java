import java.io.File;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecureFileTransfer {

	byte[] message = "I am a superman, sshhh don't tell anyone".getBytes();

	public static void main(String[] args) throws NoSuchAlgorithmException {

		
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			SecretKey aesKey = generator.generateKey();
			
			
	}
}
