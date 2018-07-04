/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.text;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.rothsmith.encrypt.text.TDesTextEncryptor;
import com.rothsmith.encrypt.text.TextEncryptionException;

/**
 * Test {@link TDesTextEncryptor} class (Triple-DES Encryptor/Decryptor).
 * 
 * @version $Revison:$
 * 
 * @author drothauser
 * 
 */
public class TDesTextEncryptorTest {

	/**
	 * This method tests encryption using a user defined password.
	 * 
	 * @see TDesTextEncryptor#encrypt(String, String)
	 * @see TDesTextEncryptor#decrypt(String, String)
	 * 
	 */
	@Test
	public final void testEncryptionWithPwd() {
		// START SNIPPET: text-encryption-pwd
		TDesTextEncryptor textEncryptor = TDesTextEncryptor.INSTANCE;
		String testString = "test-string";
		String testPwd = "secret";
		String encryptString = textEncryptor.encrypt(testString, testPwd);
		String decryptString = textEncryptor.decrypt(encryptString, testPwd);
		assertEquals(testString + " not equal " + decryptString, testString,
		    decryptString);
		// END SNIPPET: text-encryption-pwd
	}

	/**
	 * This method tests encryption using the default built-in password.
	 * 
	 * @see TDesTextEncryptor#encrypt(String)
	 * @see TDesTextEncryptor#decrypt(String)
	 * 
	 */
	@Test
	public final void testEncryptionWithoutPwd() {
		// START SNIPPET: text-encryption-nopwd
		TDesTextEncryptor textEncryptor = TDesTextEncryptor.INSTANCE;
		String testString = "test-string";
		String encryptString = textEncryptor.encrypt(testString);
		String decryptString = textEncryptor.decrypt(encryptString);
		assertEquals("testString " + testString + " not equal "
		    + decryptString, testString, decryptString);
		// END SNIPPET: text-encryption-nopwd
	}

	/**
	 * This method tests encryption using a null string.
	 * 
	 * @see TDesTextEncryptor#encrypt(String)
	 * @see TDesTextEncryptor#decrypt(String)
	 * 
	 */
	@Test(expected = TextEncryptionException.class)
	public final void testEncryptNullArgument() {

		TDesTextEncryptor textEncryptor = TDesTextEncryptor.INSTANCE;
		textEncryptor.encrypt(null);

	}

	/**
	 * This method tests decryption using a null string.
	 * 
	 * @see TDesTextEncryptor#encrypt(String)
	 * @see TDesTextEncryptor#decrypt(String)
	 * 
	 */
	@Test(expected = TextEncryptionException.class)
	public final void testDecryptNullArgument() {

		TDesTextEncryptor textEncryptor = TDesTextEncryptor.INSTANCE;
		textEncryptor.decrypt(null);

	}

}
