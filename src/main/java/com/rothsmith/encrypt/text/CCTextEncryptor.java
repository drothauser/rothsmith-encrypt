/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.text;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * *** Copied for ClaimCenter - not the real implementation ***
 * <p>
 * This class contains methods to perform encryption on sensitive data e.g.
 * social security numbers, credit card numbers etc. The Triple-DES algorithm is
 * used to perform encryption and decryption.
 * </p>
 * <p>
 * <b>Maintaining Symmetric Key Crypography Compatibility across .NET and Java 2
 * Environments:</b>
 * </p>
 * <p>
 * Fortunately, the same cryptological algorithms are implemented in both .NET
 * and Java 2 frameworks. Thus, the primary challenge in developing
 * cross-framework encryption modules is identifying the related security
 * security components of each framework. The table below identifies these
 * components:<br>
 * <table border="1">
 * <tr>
 * <td>.NET:</td>
 * <td>Java 2:</td>
 * </tr>
 * <tr>
 * <td>MD5CryptoServiceProvider</td>
 * <td>java.security.MessageDigest</td>
 * </tr>
 * <tr>
 * <td>TripleDESCryptoServiceProvider</td>
 * <td>javax.crypto.Cipher</td>
 * </tr>
 * </table>
 * <br>
 * Notice that the .NET components are more concrete than their Java
 * counterparts. In Java, the specific MessageDigest and Cipher objects are
 * created through abstract factory classes. For example:
 * 
 * <pre>
 * // Get an instance of a MessageDigest object using MD5:
 * md5 = MessageDigest.getInstance(&quot;MD5&quot;);
 * 
 * // Get an instance of a Triple-DES (DESede) cipher:
 * cipher = Cipher.getInstance(&quot;DESede/CBC/PKCS5Padding&quot;);
 * 
 * // Get an instance of a SecretKeyFactory used to create
 * // a Triple-DES key spec.
 * keyFactory = SecretKeyFactory.getInstance(&quot;DESede&quot;);
 * 
 * // Instantiate an initialization vector parameter object
 * // necessary for CBC mode:
 * ivParameter = new IvParameterSpec(IV);
 * </pre>
 * 
 * </p>
 * <p>
 * <b>Triple-DES (DESede) Encryption:</b>
 * </p>
 * <p>
 * Triple DES is a block cipher derived from the Data Encryption Standard (DES).
 * It is a mode of the DES encryption algorithm that encrypts data three times
 * using a 192 bit (24 byte) key. It encrypts data as follows:
 * <ol>
 * <li>Encrypts data with the first 8 bytes of the key.
 * <li>Encrypts the data from the first pass with the second 8 bytes of the key.
 * <li>Encrypts the data from the second pass with the third 8 bytes of the key.
 * </ol>
 * <p>
 * It should be noted that the key used in the encrypt/decrypt methods is
 * derived from the results of a MD5 hash computation (see MD5 below). This
 * results in a key of only 16 bytes. When a key of 16 bytes is used for a
 * Triple-DES cipher, the <i>DES-EDE2</i> method is used (As opposed to the
 * <i>DES-EDE3</i> method which uses a 24 byte key). When using a DES-EDE2
 * encryption key, the first 8 bytes of the key are used in the <b>first</b> and
 * <b>third</b> pass of the Triple DES algorithm; The second 8 bytes are used
 * for the second pass.
 * </p>
 * <p>
 * The .NET TripleDESCryptoServiceProvider class inherently accepts both 16 byte
 * DES-EDE2 and 24 byte DES-EDE3 encryption keys whereas the Java Tripe-DES
 * cipher only takes a DES-EDE3 key. In Java, the 24 byte key can be derived by
 * simply appending the first 8 bytes of the key to then end of the key. The
 * following code demonstrates how to do this (<i>Thanks Apache Commons for
 * ArrayUtils!</i>):
 * 
 * <pre>
 * // Get the first 8 bytes of the DES-EDE2 key.
 * // These bytes will become the 3rd 8 bytes of the
 * // Triple-DES key.
 * byte[] keyBytes1 = ArrayUtils.subarray(desEde2Key, 0, 8);
 * 
 * // Derive a 24 byte Triple-DES key (DES-EDE3) by appending
 * // the first 8 bytes of the DES-EDE2 key to the very
 * // same key.
 * byte[] desEde3Key = ArrayUtils.addAll(desEde2Key, keyBytes1);
 * </pre>
 * 
 * </p>
 * <p>
 * <b>Chained Block Cipher (CBC) Mode:</b>
 * </p>
 * <p>
 * The Triple-DES cipher used in this class employs CBC mode (Chained Block
 * Cipher) to encrypt/decrypt data. In cipher-block chaining mode, each block (8
 * bytes (64 bits)) of plaintext is XORed with the previous ciphertext block
 * before being encrypted. This causes each ciphertext block to be dependent on
 * all plaintext blocks up to that point. Furthermore, an initialization vector
 * (IV) is XORed with the first block to insure the uniqueness of the
 * ciphertext.
 * </p>
 * <br>
 * <p>
 * <b>The Initialization Vector (IV):</b>
 * <p>
 * <p>
 * An Initialization Vector is used in combination with a secret key to encrypt
 * data. It is used in CBC mode (see above) to encrypt the first block of data
 * via an XOR operation.
 * </p>
 * <br>
 * <p>
 * <b>MD5 (Message-Digest Algorithm 5):</b>
 * <p>
 * <p>
 * MD5 is a common cryptographic hash function that converts its input into a
 * 128-bit (16 byte) hash value. It is used to convert the password to a hash
 * value (16 byte array) that is used to generate the encryption key for the
 * triple-DES cipher.
 * </p>
 * 
 * @version $Id: TDesTextEncryptor.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author Doug Rothauser
 */
public enum CCTextEncryptor implements TextEncryptor {

	/**
	 * 
	 */
	// private static final TDesTextEncryptor INSTANCE =
	// new TDesTextEncryptor();

	INSTANCE;

	/**
	 * Logger for TDesTextEncryptor.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(CCTextEncryptor.class);

	/**
	 * Default password used to encrypt and decrypt data.
	 * 
	 * @see #calcP()
	 */
	private static final String DEFAULT_PWD = calcP();

	/**
	 * Block (8 bytes (64 bits)) used for cipher-block chaining mode.
	 */
	private static final int BLOCK_SIZE = 8;

	/**
	 * The number of iterations used in the password calculation algorithm.
	 */
	private static final int PASSWORD_ALGORITHM_PASSES = 30;

	/**
	 * The additive number used in the password calculation algorithm.
	 */
	private static final int PASSWORD_ALGORITHM_ADDITIVE = 49;

	/**
	 * Initialization Parameter ({@link IvParameterSpec}) used by the cipher in
	 * CBC mode.
	 * 
	 * Initialization Vector:
	 * <p>
	 * An Initialization Vector is used in combination with a secret key to
	 * encrypt data.
	 * </p>
	 * <p>
	 * The initialization vector for a VB.NET application is:
	 * </p>
	 * 
	 * <pre>
	 * Private lbtVector() As Byte = {240, 38, 45, 29, 0, 71, 171, 39}
	 * </pre>
	 * <p>
	 * Note that a byte in .NET is treated as an unsigned value ranging from 0
	 * to 255. A byte in Java is treated as a signed value ranging from -127 to
	 * 128. The VB byte numeric values can be used in a Java variable
	 * declaration as long as they are casted to a byte. Thus, this IV
	 * declaration yields the exact same in-memory byte sequence as the VB
	 * declaration:
	 * </p>
	 * 
	 * <pre>
	 * private static final byte[] IV = new byte[]
	 *  {byte) 240, (byte) 38, (byte) 45,  (byte) 29,
	 *  (byte) 0,   (byte) 71, (byte) 171, (byte) 39 };
	 * </pre>
	 */
	private final IvParameterSpec ivParameter = new IvParameterSpec(
			new byte[] { (byte) 240, (byte) 38, (byte) 45, (byte) 29, (byte) 0, (byte) 71, (byte) 171, (byte) 39 });

	/**
	 * Cryptographic cipher for encryption and decryption as implemented in the
	 * Java Cryptographic Extension (JCE).
	 */
	private Cipher cipher;

	/**
	 * {@link MessageDigest} instance which provides functionality of a message
	 * digest algorithm. This class uses MD5.
	 */
	private MessageDigest md5;

	/**
	 * Key factories are used to convert keys (opaque cryptographic keys of type
	 * {@link java.security.Key}) into key specifications (transparent
	 * representations of the underlying key material), and vice versa. Secret
	 * key factories operate only on secret (symmetric) keys.
	 * <p>
	 * This {@link SecretKeyFactory} instance will be used to create a
	 * Triple-DES {@link DESedeKeySpec} object from which the secret key will be
	 * generated.
	 * <p>
	 */
	private SecretKeyFactory keyFactory;

	/**
	 * This constructor creates the Java objects necessary to perform
	 * encyrption/decryption operations.
	 */
	private CCTextEncryptor() {

		try {
			// Get an instance of a MessageDigest object using MD5:
			md5 = MessageDigest.getInstance("MD5");

			// Get an instance of a Triple-DES (DESede) cipher:
			cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");

			// Get an instance of a SecretKeyFactory used to create
			// a Triple-DES key spec.
			keyFactory = SecretKeyFactory.getInstance("DESede");

		} catch (GeneralSecurityException e) {
			throw new TextEncryptionException("Exeption caught in TDesTextEncryptor: " + e, e);
		}

	}

	/**
	 * Get the instance of {@link TDesTextEncryptor}.
	 * 
	 * @return the instance {@link TDesTextEncryptor}.
	 */
	// public static TDesTextEncryptor newInstance() {
	// return INSTANCE;
	// }

	/**
	 * This method encrypts a given string.
	 * 
	 * <p>
	 * VB.NET EncryptString() Function:
	 * </p>
	 * 
	 * <pre>
	 * Public Function EncryptString(ByVal sInputVal As String, 
	 *           Optional ByVal sPwd As String = &quot;&quot;) As String
	 *    Dim loCryptoClass As New TripleDESCryptoServiceProvider
	 *    Dim loCryptoProvider As New MD5CryptoServiceProvider
	 *    Dim lbtBuffer() As Byte
	 * 
	 *    Try
	 *      If sPwd = &quot;&quot; Then
	 *          sPwd = CalcP()
	 *      End If
	 * 
	 *      lbtBuffer = System.Text.Encoding.UTF8.GetBytes(sInputVal)
	 *      loCryptoClass.Key = loCryptoProvider.ComputeHash(ASCIIEncoding.
	 *                    UTF8.GetBytes(sPwd))
	 *      loCryptoClass.IV = lbtVector
	 *      sInputVal = Convert.ToBase64String(loCryptoClass.CreateEncryptor().
	 *                    TransformFinalBlock(lbtBuffer, 0, lbtBuffer.Length()))
	 *      EncryptString = sInputVal
	 *  Catch ex As CryptographicException
	 *      Throw ex
	 *  Catch ex As FormatException
	 *      Throw ex
	 *  Catch ex As Exception
	 *      Throw ex
	 *  Finally
	 *      loCryptoClass.Clear()
	 *      loCryptoProvider.Clear()
	 *      loCryptoClass = Nothing
	 *      loCryptoProvider = Nothing
	 *  End Try
	 * End Function
	 * </pre>
	 * 
	 * @param input
	 *            The string to encrypt
	 * @param password
	 *            The password used to generate an encryption key for encrypting
	 *            the input string.
	 * 
	 * @return Encrypted String (Base64 Encoded)
	 */
	@Override
	public final String encrypt(final String input, final String password) {

		final boolean debugEnabled = LOGGER.isDebugEnabled();
		if (debugEnabled) {
			LOGGER.debug("enter TDesTextEncryptor encrypt(input, password)");
		}

		try {

			// Use MD5 to derive a 16 byte DES-EDE2 encryption key:
			byte[] passwordBytes = password.getBytes("UTF-8");
			byte[] desEde2Key = md5.digest(passwordBytes);

			if (debugEnabled) {
				LOGGER.debug("DES-EDE2 Key:\n" + Hex.encodeHexString(desEde2Key));
			}

			// Get the first 8 bytes of the DES-EDE2 key.
			// These bytes will become the 3rd 8 bytes of the
			// Triple-DES key.
			byte[] keyBytes1 = ArrayUtils.subarray(desEde2Key, 0, BLOCK_SIZE);
			if (debugEnabled) {
				LOGGER.debug("DES-EDE2 Key Bytes 1-8:\n" + Hex.encodeHexString(keyBytes1));
			}

			// Derive a 24 byte Triple-DES key (DES-EDE3) by appending
			// the first 8 bytes of the DES-EDE2 key to the very
			// same key.
			byte[] desEde3Key = ArrayUtils.addAll(desEde2Key, keyBytes1);
			if (debugEnabled) {
				LOGGER.debug("24 byte Triple-DES Key:\n" + Hex.encodeHexString(desEde3Key));
			}

			// Create a Triple-DES key suitable for the cipher:
			DESedeKeySpec keySpec = new DESedeKeySpec(desEde3Key);
			SecretKey key = keyFactory.generateSecret(keySpec);

			// Initialize the cipher and put it into encrypt mode
			cipher.init(Cipher.ENCRYPT_MODE, key, ivParameter);

			// Encrypt the data
			if (debugEnabled) {
				LOGGER.debug("Input String:\n" + input);
			}
			byte[] plaintext = input.getBytes("UTF-8");
			byte[] encrypted = cipher.doFinal(plaintext);

			String encryptedString = Base64.encodeBase64String(encrypted);

			if (debugEnabled) {
				LOGGER.debug("Encrypted-Base64 Encoded String:\n" + encryptedString);
			}

			return encryptedString;

		} catch (Exception e) {
			String msg = "Encryption exception caught: " + e;
			LOGGER.error(msg);
			throw new TextEncryptionException(msg, e);
		}

	}

	/**
	 * This method encrypts a given string.
	 * 
	 * @param input
	 *            The string to encrypt
	 * 
	 * @return the encrypted input string (Base64 Encoded)
	 * 
	 * @see #encrypt(String, String)
	 * @see #calcP()
	 */
	@Override
	public final String encrypt(final String input) {
		// Encrypt the input string using the
		// password generated by the calcP() method.

		final boolean debugEnabled = LOGGER.isDebugEnabled();
		if (debugEnabled) {
			LOGGER.debug("enter TDesTextEncryptor encrypt(input)");
		}

		String encryptedString = encrypt(input, DEFAULT_PWD);

		if (debugEnabled) {
			LOGGER.debug("exit TDesTextEncryptor encrypt(input)");
		}

		return encryptedString;
	}

	/**
	 * This method decrypts a given string. The input string is expected to be
	 * Base64 encoded.
	 * 
	 * <p>
	 * VB.NET DecryptString() Function:
	 * </p>
	 * 
	 * 
	 * <pre>
	 * Public Function DecryptString(ByVal sQueryString As String, 
	 *            Optional ByVal sPwd As String = &quot;&quot;) As String
	 *  Dim buffer() As Byte
	 *  Dim loCryptoClass As New TripleDESCryptoServiceProvider
	 *  Dim loCryptoProvider As New MD5CryptoServiceProvider
	 * 
	 *  Try
	 *      If sPwd = &quot;&quot; Then
	 *          sPwd = CalcP()
	 *      End If
	 *      buffer = Convert.FromBase64String(sQueryString)
	 *      loCryptoClass.Key = loCryptoProvider.
	 *             ComputeHash(ASCIIEncoding.UTF8.GetBytes(sPwd))
	 *      loCryptoClass.IV = lbtVector
	 *      Return Encoding.UTF8.GetString(loCryptoClass.CreateDecryptor().
	 *             TransformFinalBlock(buffer, 0, buffer.Length()))
	 *  Catch ex As Exception
	 *      Throw ex
	 *  Finally
	 *      loCryptoClass.Clear()
	 *      loCryptoProvider.Clear()
	 *      loCryptoClass = Nothing
	 *      loCryptoProvider = Nothing
	 *  End Try
	 * End Function
	 * </pre>
	 * 
	 * @param input
	 *            Encrypted string (Base64 Encoded)
	 * @param password
	 *            The password used to generate an encryption key for decrypting
	 *            the input string.
	 * 
	 * @return the decrypted input string
	 * 
	 */
	@Override
	public final String decrypt(final String input, final String password) {

		final boolean debugEnabled = LOGGER.isDebugEnabled();

		try {

			// Use MD5 to derive a 16 byte DES-EDE2 encryption key:
			byte[] passwordBytes = password.getBytes("UTF-8");
			byte[] desEde2Key = md5.digest(passwordBytes);
			if (debugEnabled) {
				LOGGER.debug("DES-EDE2 Key:\n" + Hex.encodeHexString(desEde2Key));
			}

			// Get the first 8 bytes of the DES-EDE2 key.
			// These bytes will become the 3rd 8 bytes of the
			// Triple-DES key.
			byte[] keyBytes1 = ArrayUtils.subarray(desEde2Key, 0, BLOCK_SIZE);
			if (debugEnabled) {
				LOGGER.debug("DES-EDE2 Key Bytes 1-8:\n" + Hex.encodeHexString(keyBytes1));
			}

			// Derive a 24 byte Triple-DES key (DES-EDE3) by appending
			// the first 8 bytes of the DES-EDE2 key to the very
			// same key.
			byte[] desEde3Key = ArrayUtils.addAll(desEde2Key, keyBytes1);
			if (debugEnabled) {
				LOGGER.debug("24 byte Triple-DES Key:\n" + Hex.encodeHexString(desEde3Key));
			}

			// Create a Triple-DES key suitable for the cipher:
			DESedeKeySpec keySpec = new DESedeKeySpec(desEde3Key);
			SecretKey key = keyFactory.generateSecret(keySpec);

			// Initialize the cipher and put it into encrypt mode
			cipher.init(Cipher.DECRYPT_MODE, key, ivParameter);

			// Decrypt the data
			if (debugEnabled) {
				LOGGER.debug("Input String:\n" + input);
			}

			byte[] encryptedBytes = Base64.decodeBase64(input);

			byte[] decrypted = cipher.doFinal(encryptedBytes);

			String decryptedString = StringUtils.newStringUtf8(decrypted);

			if (debugEnabled) {
				LOGGER.debug("Decrypted String:\n" + decryptedString);
			}

			return decryptedString;

		} catch (Exception e) {
			String msg = "Decryption exception caught: " + e;
			LOGGER.error(msg);
			throw new TextEncryptionException(msg, e);
		}

	}

	/**
	 * This method decrypts a given string. The input string is expected to be
	 * Base64 encoded. It uses the same algorithm as the Card system's.
	 * 
	 * @param input
	 *            Encrypted string (Base64 Encoded)
	 * @return Decrypted String
	 */
	@Override
	public final String decrypt(final String input) {

		String decryptedString = decrypt(input, DEFAULT_PWD);

		return decryptedString;
	}

	/**
	 * This method returns a default password using the algorithm below.
	 * <p>
	 * VB.NET CalcP() Function:
	 * </p>
	 * 
	 * <pre>
	 * Public Function CalcP() As String
	 *   Dim sVal As String
	 *   Dim i As Integer
	 * 
	 *   'Calculate it
	 *   For i = 1 To 30 Step 2  
	 *      sVal += i.ToString &amp; Chr(i + 49)
	 *   Next i
	 * 
	 *   Return sVal
	 * End Function
	 * </pre>
	 * 
	 * This function will always return:<br>
	 * 
	 * <pre>
	 * <code>123456789:11&lt;13&gt;15@17B19D21F23H25J27L29N</code>
	 * </pre>
	 * 
	 * @return String containing the default password.
	 */
	private static String calcP() {

		final boolean debugEnabled = LOGGER.isDebugEnabled();

		String sVal = "";

		StringBuffer sb = new StringBuffer();

		for (int i = 1; i <= PASSWORD_ALGORITHM_PASSES; i = i + 2) {
			char c = (char) (i + PASSWORD_ALGORITHM_ADDITIVE);
			sb.append(i);
			sb.append(c);
		}

		sVal = sb.toString();

		if (debugEnabled) {
			LOGGER.debug("Generated Password:\n" + sVal);
		}

		return sVal;

	}

}
