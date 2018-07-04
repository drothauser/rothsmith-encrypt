/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 * @author drothauser
 * 
 */
public class BcPGPKeyGenTest {

	/**
	 * Temporary test folder.
	 */
	@Rule
	// CHECKSTYLE:OFF Ignore private requirement for unit testing.
	public TemporaryFolder folder = new TemporaryFolder();

	// CHECKSTYLE:ON

	/**
	 * PGP recipient/user id.
	 */
	private static final String RECIPIENT = "fccitest";

	/**
	 * Pass phrase.
	 */
	private static final String PASSPHRASE = "test4u";

	/**
	 * Public key ring file.
	 */
	private File pubringFile;

	/**
	 * Secret (private) key ring file.
	 */
	private File secringFile;

	/**
	 * {@link BcPGPKeyGen} to test.
	 */
	private BcPGPKeyGen keyGen = new BcPGPKeyGen();

	/**
	 * Set up test fixture.
	 * 
	 * @throws java.lang.Exception
	 *             possible error.
	 */
	@Before
	public void setUp() throws Exception {

		pubringFile = folder.newFile("pubring.gpg");
		secringFile = folder.newFile("secring.gpg");

		keyGen = new BcPGPKeyGen();
	}

	// CHECKSTYLE:OFF @link doesn't wrap at 80 characters
	/**
	 * Test method for
	 * {@link BcPGPKeyGen#exportKeyPair(OutputStream, OutputStream, String, String, boolean)}
	 * .
	 * 
	 * @throws IOException
	 *             Possible I/O error.
	 */
	// CHECKSTYLE: ON
	@Test
	public void testExportKeyPair() throws IOException {

		FileOutputStream secringOut = new FileOutputStream(secringFile);
		FileOutputStream pubringOut = new FileOutputStream(pubringFile);
		boolean isArmored = true;
		keyGen.exportKeyPair(secringOut, pubringOut, RECIPIENT, PASSPHRASE, isArmored);

		assertTrue(StringUtils.contains(FileUtils.readFileToString(secringFile), "BEGIN PGP PRIVATE KEY"));
		assertTrue(StringUtils.contains(FileUtils.readFileToString(pubringFile), "BEGIN PGP PUBLIC KEY"));

	}

	// CHECKSTYLE:OFF @link doesn't wrap at 80 characters
	/**
	 * Test method for
	 * {@link BcPGPKeyGen#exportKeyPair(OutputStream, OutputStream, String, String, boolean)}
	 * using no armor.
	 * 
	 * @throws IOException
	 *             Possible I/O error.
	 */
	// CHECKSTYLE: ON
	@Test
	public void testExportKeyPairNoArmor() throws IOException {

		FileOutputStream secringOut = new FileOutputStream(secringFile);
		FileOutputStream pubringOut = new FileOutputStream(pubringFile);
		boolean isArmored = false;
		keyGen.exportKeyPair(secringOut, pubringOut, RECIPIENT, PASSPHRASE, isArmored);

		assertFalse(StringUtils.contains(FileUtils.readFileToString(secringFile), "BEGIN PGP PRIVATE KEY"));
		assertFalse(StringUtils.contains(FileUtils.readFileToString(pubringFile), "BEGIN PGP PUBLIC KEY"));

	}

	// CHECKSTYLE:OFF @link doesn't wrap at 80 characters
	/**
	 * Test method for
	 * {@link BcPGPKeyGen#exportKeyPair(OutputStream, OutputStream, String, String, boolean)}
	 * with null FileOutputStream parameter.
	 * 
	 * @throws IOException
	 *             Possible I/O error.
	 */
	// CHECKSTYLE: ON
	@Test(expected = RuntimeException.class)
	public void testExportKeyPairBadParam() throws IOException {

		FileOutputStream pubringOut = new FileOutputStream(pubringFile);
		boolean isArmored = true;
		keyGen.exportKeyPair(null, pubringOut, RECIPIENT, PASSPHRASE, isArmored);

	}

}
