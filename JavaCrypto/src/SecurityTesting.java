import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.util.Scanner;

import javax.crypto.ShortBufferException;

public class SecurityTesting {
	/**
	 * For the test:
	 * 
	 * 1. I create 2 File object (contains plaintext and the cipher one)
	 * 2. With the EncryptFile class we encrypt the plaintext and write into the cipher.txt
	 * 3. I read both plaintext and ciphertext to see if it works.
	 * 
	 */
	
	public static void main(String[] args) {
		
		File plaintext = new File("plaintext.txt");
		File cipher = new File("cipher.txt");
		FileInputStream fis = null;
		FileOutputStream fos = null;
		FileInputStream readCipher = null;
		
		try {
			//Encrypt the plaintext with the EncryptFile class
			EncryptFile.encryptFile(plaintext, cipher);
			fis = new FileInputStream(plaintext);
			readCipher = new FileInputStream(cipher);
			
			//Reads the plaintext file (the file is in JavaCrypto dir)
			System.out.println("Total file size to read (in bytes) : "
					+ fis.available());
 
			int content;
			while ((content = fis.read()) != -1) {
				// convert to char and display it
				System.out.print((char) content);
			}
			
			//Reads the cipher file (the file is in JavaCrypto dir)
			System.out.println("Let's check the cipher text");
			
			System.out.println("Total file size to read (in bytes) : "
					+ readCipher.available());
 
			while ((content = readCipher.read()) != -1) {
				// convert to char and display it
				System.out.print((char) content);
			}
			
		} catch (ShortBufferException | InvalidAlgorithmParameterException
				| CryptoException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}finally {
			try {
				if (fis != null)
					fis.close();
			} catch (IOException ex) {
				ex.printStackTrace();
			}
		}
		
	}

}