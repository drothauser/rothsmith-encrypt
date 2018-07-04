/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.junit.BeforeClass;
import org.junit.Test;

import com.rothsmith.encrypt.pgp.BcPGP;
import com.rothsmith.encrypt.pgp.BcPGPKeyGen;
import com.rothsmith.encrypt.pgp.PGPEncryptionException;
import com.rothsmith.encrypt.pgp.PGPParams;

/**
 * Tests for BouncyCastle PGP file encryption.
 * 
 * @version $Id: BcPGPTest.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author drothauser
 * 
 */
@SuppressWarnings("PMD.AvoidDuplicateLiterals")
public class BcPGPTest {

	/**
	 * Temporary test folder.
	 */
	private static final String FOLDER = new File(
	    System.getProperty("java.io.tmpdir")).getAbsolutePath();

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
	private static File testFile;

	/**
	 * Public key ring file.
	 */
	private static File pubringFile;

	/**
	 * Secret (private) key ring file.
	 */
	private static File secringFile;

	/**
	 * Generate a temporary public and secret ring file prior to running the
	 * tests.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@BeforeClass
	public static void setUpBeforeClass() throws IOException {

		testFile = new File(FOLDER + File.separator + TEST_FILE_NAME);

		FileUtils.writeStringToFile(testFile,
		    "Hello World ABCDEFG 1234567890");

		pubringFile = new File(FOLDER + File.separator + "pubring.gpg");
		secringFile = new File(FOLDER + File.separator + "secring.gpg");

		BcPGPKeyGen keyGen = new BcPGPKeyGen();

		FileOutputStream secringOut = new FileOutputStream(secringFile);
		FileOutputStream pubringOut = new FileOutputStream(pubringFile);
		boolean isArmored = true;
		keyGen.exportKeyPair(secringOut, pubringOut, RECIPIENT, PASSPHRASE,
		    isArmored);

	}

	/**
	 * Test method for {@link BcPGP#encrypt(String, String)}.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test
	public final void testEncrypt() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";
		bcPGP.decrypt(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksumCRC32(new File(unencryptedFile)),
		    FileUtils.checksumCRC32(new File(verifyFile)));
	}

	/**
	 * Test method for {@link BcPGP#encrypt(String, String)} with and invalid
	 * public key ring file.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testEncryptInvalidKeyring() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile("bogus");
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		new BcPGP(pgpParams).encrypt(unencryptedFile, encFile);

	}

	/**
	 * Test method for {@link BcPGP#encrypt(String, String)} without using
	 * armor.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test
	public final void testEncryptNoArmor() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(false);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";
		bcPGP.decrypt(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksumCRC32(new File(unencryptedFile)),
		    FileUtils.checksumCRC32(new File(verifyFile)));
	}

	/**
	 * Test method for {@link BcPGP#encrypt(String, String)} using an invalid
	 * input file.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testEncryptInvalidInput() throws IOException {

		String unencryptedFile = "bogus.txt";
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";
		bcPGP.decrypt(encFile, verifyFile);

		assertEquals(
		    "Expected original and unencrypted files to be the same",
		    FileUtils.checksumCRC32(new File(unencryptedFile)),
		    FileUtils.checksumCRC32(new File(verifyFile)));
	}

	/**
	 * Test method for {@link BcPGP#decrypt(String, String)} using an invalid
	 * passphrase.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testDecryptInvalidPassphrase() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase("bogus");

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";
		bcPGP.decrypt(encFile, verifyFile);

	}

	/**
	 * Test method for {@link BcPGP#decrypt(String, String)} using an invalid
	 * secret/private key ring file.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testDecryptInvalidKeyring() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile("bogus");
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";
		bcPGP.decrypt(encFile, verifyFile);

	}

	/**
	 * Test method for {@link BcPGP#decrypt(String, String)} using an invalid
	 * input file.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testDecryptInvalidInputFile() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient(RECIPIENT);
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

		String verifyFile =
		    FilenameUtils.removeExtension(unencryptedFile) + "-verify.txt";

		bcPGP.decrypt("bogus", verifyFile);

	}

	/**
	 * Test method for {@link BcPGP#encrypt(String, String)} using an invalid
	 * recipient.
	 * 
	 * @throws IOException
	 *             possible I/O error
	 */
	@Test(expected = PGPEncryptionException.class)
	public final void testEncryptInvalidRecipient() throws IOException {

		String unencryptedFile = testFile.getAbsolutePath();
		String encFile = unencryptedFile + PGP_EXT;

		PGPParams pgpParams = new PGPParams();
		pgpParams.setArmored(true);
		pgpParams.setPubKeyRingFile(pubringFile.getAbsolutePath());
		pgpParams.setSecKeyRingFile(secringFile.getAbsolutePath());
		pgpParams.setRecipient("bogus");
		pgpParams.setPassPhrase(PASSPHRASE);

		BcPGP bcPGP = new BcPGP(pgpParams);
		bcPGP.encrypt(unencryptedFile, encFile);

	}

}
