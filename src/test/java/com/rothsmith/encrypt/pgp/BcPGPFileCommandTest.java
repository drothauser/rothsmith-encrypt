/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.CRC32;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.crypto.CryptoException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import com.rothsmith.encrypt.pgp.BcPGPDecryptCommand;
import com.rothsmith.encrypt.pgp.BcPGPEncryptCommand;
import com.rothsmith.encrypt.pgp.BcPGPKeyGen;
import com.rothsmith.encrypt.pgp.PGPFileCommand;

/**
 * Tests for {@link BcPGPEncryptCommand}.
 * 
 * @version $Revision: 765 $
 * 
 * @author drothauser
 * 
 */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
public class BcPGPFileCommandTest {

	/**
	 * Temporary test folder.
	 */
	@Rule
	// CHECKSTYLE:OFF Ignore private requirement for unit testing.
	public TemporaryFolder folder = new TemporaryFolder();
	// CHECKSTYLE:ON

	/**
	 * PGP file extension.
	 */
	private static final String PGP_EXT = ".pgp";

	/**
	 * PGP recipient/user id.
	 */
	private static final String RECIPIENT = "fccitest";

	/**
	 * Pass phrase.
	 */
	private static final String PASSPHRASE = "test4u";

	/**
	 * Test file resource.
	 */
	private static final String TEST_FILE_NAME = "pgptest.txt";

	/**
	 * Test file to test encryption and decryption.
	 */
	private File testFile;

	/**
	 * Public key ring file.
	 */
	private File pubringFile;

	/**
	 * Secret (private) key ring file.
	 */
	private File secringFile;

	/**
	 * Set up test file and PGP encryption key for all tests.
	 * 
	 * @throws IOException
	 *             Possible I/O error.
	 */
	@Before
	public void setUp() throws IOException {

		testFile = folder.newFile(TEST_FILE_NAME);

		FileUtils.writeStringToFile(testFile,
		    "Hello World ABCDEFG 1234567890");

		pubringFile = folder.newFile("pubring.gpg");
		secringFile = folder.newFile("secring.gpg");

		BcPGPKeyGen keyGen = new BcPGPKeyGen();

		FileOutputStream secringOut = new FileOutputStream(secringFile);
		FileOutputStream pubringOut = new FileOutputStream(pubringFile);
		boolean isArmored = true;
		keyGen.exportKeyPair(secringOut, pubringOut, RECIPIENT, PASSPHRASE,
		    isArmored);

	}

	/**
	 * Test method for {@link BcPGPEncryptCommand#execute(String, String)} with
	 * armor and no integrity check.
	 * 
	 * @throws CryptoException
	 *             possible cryptographic error
	 * @throws IOException
	 *             possible I/O error
	 * 
	 */
	@Test
	public final void testExecuteArmorNoIntegrity() throws CryptoException,
	        IOException {

		boolean armor = true;
		boolean integrityCheck = false;

		BcPGPEncryptCommand pgpEncryptCommand =
		    new BcPGPEncryptCommand(pubringFile.getAbsolutePath(),
		        RECIPIENT, armor, integrityCheck);

		String file = testFile.getAbsolutePath();
		String encFile = file + PGP_EXT;

		pgpEncryptCommand.execute(file, encFile);

		PGPFileCommand pgpDecryptCommand =
		    new BcPGPDecryptCommand(secringFile.getAbsolutePath(),
		        PASSPHRASE);

		String verifyFile =
		    FilenameUtils.removeExtension(file) + "-verify.txt";
		pgpDecryptCommand.execute(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksum(new File(file), new CRC32()).getValue(),
		    FileUtils.checksum(new File(verifyFile), new CRC32()).getValue());
	}

	/**
	 * Test method for {@link BcPGPEncryptCommand#execute(String, String)} with
	 * armor and integrity check.
	 * 
	 * @throws CryptoException
	 *             possible cryptographic error
	 * @throws IOException
	 *             possible I/O error
	 * 
	 */
	@Test
	public final void testExecuteArmorIntegrity() throws CryptoException,
	        IOException {

		boolean armor = true;
		boolean integrityCheck = true;

		BcPGPEncryptCommand pgpEncryptCommand =
		    new BcPGPEncryptCommand(pubringFile.getAbsolutePath(),
		        RECIPIENT, armor, integrityCheck);

		String file = testFile.getAbsolutePath();
		String encFile = file + PGP_EXT;

		pgpEncryptCommand.execute(file, encFile);

		PGPFileCommand pgpDecryptCommand =
		    new BcPGPDecryptCommand(secringFile.getAbsolutePath(),
		        PASSPHRASE);

		String verifyFile =
		    FilenameUtils.removeExtension(file) + "-verify.txt";
		pgpDecryptCommand.execute(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksum(new File(file), new CRC32()).getValue(),
		    FileUtils.checksum(new File(verifyFile), new CRC32()).getValue());
	}

	/**
	 * Test method for {@link BcPGPEncryptCommand#execute(String, String)} with
	 * no armor and no integrity check.
	 * 
	 * @throws CryptoException
	 *             possible cryptographic error
	 * @throws IOException
	 *             possible I/O error
	 * 
	 */
	@Test
	public final void testExecuteNoArmorNoIntegrity()
	        throws CryptoException, IOException {

		boolean armor = false;
		boolean integrityCheck = false;

		BcPGPEncryptCommand pgpEncryptCommand =
		    new BcPGPEncryptCommand(pubringFile.getAbsolutePath(),
		        RECIPIENT, armor, integrityCheck);

		String file = testFile.getAbsolutePath();
		String encFile = file + PGP_EXT;

		pgpEncryptCommand.execute(file, encFile);

		PGPFileCommand pgpDecryptCommand =
		    new BcPGPDecryptCommand(secringFile.getAbsolutePath(),
		        PASSPHRASE);

		String verifyFile =
		    FilenameUtils.removeExtension(file) + "-verify.txt";
		pgpDecryptCommand.execute(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksum(new File(file), new CRC32()).getValue(),
		    FileUtils.checksum(new File(verifyFile), new CRC32()).getValue());
	}

	/**
	 * Test method for {@link BcPGPEncryptCommand#execute(String, String)} with
	 * no armor and integrity check.
	 * 
	 * @throws CryptoException
	 *             possible cryptographic error
	 * @throws IOException
	 *             possible I/O error
	 * 
	 */
	@Test
	public final void testExecuteNoArmorIntegrity() throws CryptoException,
	        IOException {

		// START SNIPPET: pgp-encrypt
		boolean armor = false;
		boolean integrityCheck = true;

		BcPGPEncryptCommand pgpEncryptCommand =
		    new BcPGPEncryptCommand(pubringFile.getAbsolutePath(),
		        RECIPIENT, armor, integrityCheck);

		String file = testFile.getAbsolutePath();
		String encFile = file + PGP_EXT;

		pgpEncryptCommand.execute(file, encFile);
		// END SNIPPET: pgp-encrypt

		// START SNIPPET: pgp-decrypt
		PGPFileCommand pgpDecryptCommand =
		    new BcPGPDecryptCommand(secringFile.getAbsolutePath(),
		        PASSPHRASE);

		String verifyFile =
		    FilenameUtils.removeExtension(file) + "-verify.txt";
		pgpDecryptCommand.execute(encFile, verifyFile);
		// END SNIPPET: pgp-decrypt

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksum(new File(file), new CRC32()).getValue(),
		    FileUtils.checksum(new File(verifyFile), new CRC32()).getValue());
	}

}
