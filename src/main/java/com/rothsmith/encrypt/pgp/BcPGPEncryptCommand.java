/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Command for encrypting a file using BouncyCastle PGP.
 * 
 * @version $Revision: 757 $
 * 
 * @author drothauser
 * 
 */
public final class BcPGPEncryptCommand implements PGPFileCommand {

	/**
	 * Logger for BcPGPEncryptCommand.
	 */
	private static final Logger LOGGER = LoggerFactory
	    .getLogger(BcPGPEncryptCommand.class);

	/**
	 * The PGP public key ring file.
	 */
	private final String keyRingFile;

	/**
	 * The recipient (user) id of the public key used for encryption.
	 */
	private final String recipient;

	/**
	 * If true, it causes PGP to emit ciphertext or keys in ASCII Radix-64
	 * format suitable for transporting through E-mail channels.
	 */
	private final boolean armored;

	/**
	 * Should encrypted data have integrity check?
	 */
	private final boolean integrityCheck;

	/**
	 * Default constructor.
	 * 
	 * @param pgpParams
	 *            PGP parameters
	 */
	/**
	 * Constructor that initializes the keyRingFile and recipient fields.
	 * 
	 * @param keyRingFile
	 *            the key ring file that contains the public keys used to
	 *            encrypt data.
	 * @param recipient
	 *            The user id of the key used for encryption.
	 * @param armored
	 *            If true, it causes PGP to emit ciphertext or keys in ASCII
	 *            Radix-64 format suitable for transporting through E-mail
	 *            channels.
	 * @param integrityCheck
	 *            Should encrypted data have integrity check?
	 */
	public BcPGPEncryptCommand(final String keyRingFile,
	    final String recipient, final boolean armored,
	    final boolean integrityCheck) {

		Security.addProvider(new BouncyCastleProvider());

		this.keyRingFile = keyRingFile;
		this.recipient = recipient;
		this.armored = armored;
		if (!armored && integrityCheck) {
			LOGGER
			    .warn("Integrity checking doesn't work without armor option.");
			this.integrityCheck = false;
		} else {
			this.integrityCheck = integrityCheck;
		}

	}

	/**
	 * This method encrypts the input file to the given output file.
	 * 
	 * @param inputFile
	 *            The file to encrypt
	 * @param outputFile
	 *            The encrypted file
	 */
	public void execute(final String inputFile, final String outputFile) {

		OutputStream out = null;
		OutputStream cOut = null;

		try {

			FileOutputStream fos = new FileOutputStream(outputFile);
			out = (armored) ? new ArmoredOutputStream(fos) : fos;

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			PGPCompressedDataGenerator comData =
			    new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

			// CHECKSTYLE:OFF magic number ok here
			PGPUtil.writeFileToLiteralData(
			    comData.open(bOut, new byte[1 << 16]),
			    PGPLiteralData.BINARY, new File(inputFile));
			// CHECKSTYLE:ON

			comData.close();

			PGPEncryptedDataGenerator cPk =
			    new PGPEncryptedDataGenerator(PGPEncryptedData.CAST5,
			        integrityCheck, new SecureRandom(), "BC");

			PGPPublicKey encKey = readPublicKey(keyRingFile, recipient);
			cPk.addMethod(encKey);

			byte[] bytes = bOut.toByteArray();

			cOut = cPk.open(out, bytes.length);

			cOut.write(bytes);

			out.flush();
			cOut.flush();

		} catch (Exception e) {
			throw new PGPEncryptionException(
			    "Exception caught in BcPGPEncryptCommand.execute: " + e, e);
		} finally {
			IOUtils.closeQuietly(cOut);
			IOUtils.closeQuietly(out);
		}

	}

	/**
	 * A simple routine that opens a key ring file and loads the first available
	 * key suitable for encryption.
	 * 
	 * @param keyRingFile
	 *            key ring file name
	 * @param recipient
	 *            the user id owning the key ring(s)
	 * @return a {@link PGPPublicKey} object
	 * @throws IOException
	 *             possible I/O error
	 * @throws PGPException
	 *             possible PGP error
	 */
	@SuppressWarnings("unchecked")
	private static PGPPublicKey readPublicKey(final String keyRingFile,
	    final String recipient) throws IOException, PGPException {

		FileInputStream keyIn = new FileInputStream(keyRingFile);

		InputStream in = PGPUtil.getDecoderStream(keyIn);

		PGPPublicKeyRingCollection pgpPub =
		    new PGPPublicKeyRingCollection(in);

		Iterator<PGPPublicKeyRing> rIt =
		    pgpPub.getKeyRings(recipient, true, true);

		while (rIt.hasNext()) {
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();

			while (kIt.hasNext()) {
				PGPPublicKey k = (PGPPublicKey) kIt.next();

				if (k.isEncryptionKey()) {
					return k;
				}
			}
		}

		throw new IllegalArgumentException(String.format(
		    "Can't find encryption key for "
		        + "recipient/user id '%s' in key ring file: %s", recipient,
		    keyRingFile));
	}

}
