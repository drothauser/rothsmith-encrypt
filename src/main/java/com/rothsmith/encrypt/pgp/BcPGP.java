/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

/**
 * Class for encrypting and decrypting files using BouncyCastle.
 * <p>
 * <b>IMPORTANT: </b>The <b><i>&quot;Unlimited Strength Java(TM) Cryptography
 * Extension Policy Files for the Java(TM) Platform, Standard Edition
 * Development Kit, v6&quot;</i></b> is required for Bouncy Castle's
 * cryptography libraries. It must be installed into the <b>
 * %JAVA_HOME%/jre/lib/security</b> folder. It can be downloaded from <a
 * href="http://www.oracle.com/technetwork/
 * java/javase/downloads/jce-6-download-429243.html">here</a>. Refer to the
 * README.txt in the downloaded zip file for more information.
 * </p>
 * 
 * @version $Id: BcPGP.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author drothauser
 * 
 */
public class BcPGP implements PGP {

	/**
	 * BouncyCastle Encryptable Command.
	 */
	private final PGPFileCommand pgpEncryptCommand;

	/**
	 * BouncyCastle Decryption Command.
	 */
	private final BcPGPDecryptCommand pgpDecryptCommand;

	/**
	 * Constructor that initializes the pgpParams field.
	 * 
	 * @param pgpParams
	 *            PGP parameters for encrypt/decrypt operations
	 */
	public BcPGP(final PGPParams pgpParams) {

		pgpEncryptCommand =
		    new BcPGPEncryptCommand(pgpParams.getPubKeyRingFile(),
		        pgpParams.getRecipient(), pgpParams.isArmored(),
		        pgpParams.isIntegrityCheck());

		pgpDecryptCommand =
		    new BcPGPDecryptCommand(pgpParams.getSecKeyRingFile(),
		        pgpParams.getPassPhrase());

	}

	/**
	 * {@inheritDoc}
	 */
	public final void encrypt(final String inputFile, final String outputFile) {

		pgpEncryptCommand.execute(inputFile, outputFile);

	}

	/**
	 * {@inheritDoc}
	 */
	public final void decrypt(final String inputFile, final String outputFile) {

		pgpDecryptCommand.execute(inputFile, outputFile);

	}

}
