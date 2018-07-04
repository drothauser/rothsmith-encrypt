/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Command for encrypting a file using BouncyCastle PGP.
 * 
 * @version $Id: BcPGPDecryptCommand.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author drothauser
 * 
 */
@SuppressWarnings("PMD.CyclomaticComplexity")
public final class BcPGPDecryptCommand implements PGPFileCommand {

	/**
	 * Logger for BcPGPDecryptCommand.
	 */
	private static final Logger LOGGER = LoggerFactory
	    .getLogger(BcPGPDecryptCommand.class);

	/**
	 * The PGP private (secret) key ring file.
	 */
	private final String keyRingFile;

	/**
	 * The pass phrase for decrypting with the private key.
	 */
	private final String passPhrase;

	/**
	 * Constructor that initializes the keyRingFile and passPhrase fields.
	 * 
	 * @param keyRingFile
	 *            The PGP private (secret) key ring file
	 * @param passPhrase
	 *            The pass phrase for decrypting with the private key
	 */
	public BcPGPDecryptCommand(final String keyRingFile,
	    final String passPhrase) {

		Security.addProvider(new BouncyCastleProvider());

		this.keyRingFile = keyRingFile;
		this.passPhrase = passPhrase;

	}

	/**
	 * {@inheritDoc}
	 */
	// CHECKSTYLE:OFF High Cyclomatic complexity due to encryption complexity.
	// TODO - Refactor - this method was more or less copied from a poorly
	// written example.
	@SuppressWarnings({ "PMD.ExcessiveMethodLength", "PMD.NPathComplexity" })
	public void execute(final String inFile, final String outFile) {

		InputStream in = null;
		FileOutputStream fOut = null;
		try {
			in =
			    PGPUtil.getDecoderStream(new FileInputStream(
			        new File(inFile)));

			PGPObjectFactory pgpF = new PGPObjectFactory(in);

			Object o = pgpF.nextObject();

			// the first object might be a PGP marker packet.
			PGPEncryptedDataList enc =
			    (o instanceof PGPEncryptedDataList) ? (PGPEncryptedDataList) o
			        : (PGPEncryptedDataList) pgpF.nextObject();

			PGPPrivateKey sKey = null;
			PGPPublicKeyEncryptedData pbe = null;

			PGPSecretKeyRingCollection pgpSec =
			    new PGPSecretKeyRingCollection(
			        PGPUtil
			            .getDecoderStream(new FileInputStream(keyRingFile)));

			// find the secret key
			@SuppressWarnings("unchecked")
			Iterator<PGPPublicKeyEncryptedData> it =
			    enc.getEncryptedDataObjects();

			while (sKey == null && it.hasNext()) {
				pbe = it.next();
				sKey = findSecretKey(pgpSec, pbe.getKeyID(), passPhrase);
			}

			if (sKey == null) {
				throw new IllegalArgumentException(
				    "secret key for message not found.");
			}

			// TODO - refactor to avoid null pbe.
			@SuppressWarnings("null")
			InputStream clear = pbe.getDataStream(sKey, "BC");

			PGPObjectFactory plainFact = new PGPObjectFactory(clear);

			Object message = plainFact.nextObject();

			if (message instanceof PGPCompressedData) {
				PGPCompressedData cData = (PGPCompressedData) message;
				PGPObjectFactory pgpFact =
				    new PGPObjectFactory(cData.getDataStream());

				message = pgpFact.nextObject();
			}

			if (message instanceof PGPLiteralData) {
				PGPLiteralData ld = (PGPLiteralData) message;

				fOut = new FileOutputStream(outFile);

				InputStream unc = ld.getInputStream();
				int ch;
				while ((ch = unc.read()) >= 0) { // NOPMD assign operand ok here
					fOut.write(ch);
				}
			} else if (message instanceof PGPOnePassSignatureList) {
				throw new CryptoException(
				    "encrypted message contains a signed message "
				        + "- not literal data.");
			} else {
				throw new CryptoException(
				    "message is not a simple encrypted file "
				        + "- type unknown.");
			}

			if (pbe.isIntegrityProtected()) {
				if (pbe.verify()) {
					LOGGER.info("message integrity check passed");
				} else {
					LOGGER.error("message failed integrity check");
				}
			} else {
				LOGGER.info("no message integrity check");
			}

		} catch (CryptoException e) {
			throw new PGPEncryptionException(
			    "CryptoException caught in BcPGPDecryptCommand.execute: "
			        + e, e);
		} catch (IOException e) {
			throw new PGPEncryptionException(
			    "IOException caught in BcPGPDecryptCommand.execute: " + e, e);
		} catch (PGPException e) {
			throw new PGPEncryptionException(
			    "PGPException caught in BcPGPDecryptCommand.execute: " + e,
			    e);
		} catch (NoSuchProviderException e) {
			throw new PGPEncryptionException(
			    "NoSuchProviderException caught in BcPGPDecryptCommand.execute: "
			        + e, e);
		} finally {
			IOUtils.closeQuietly(in);
			IOUtils.closeQuietly(fOut);
		}

	}

	/**
	 * Search a secret key ring collection for a secret key corresponding to
	 * keyID if it exists.
	 * 
	 * @param pgpSec
	 *            a secret key ring collection.
	 * @param keyID
	 *            keyID we want.
	 * @param passPhrase
	 *            passphrase to decrypt secret key with.
	 * @return {@link PGPPrivateKey} object
	 * @throws PGPException
	 *             possible PGP error
	 * @throws NoSuchProviderException
	 *             possible {@link NoSuchProviderException}
	 */
	private PGPPrivateKey findSecretKey(
	    final PGPSecretKeyRingCollection pgpSec, final long keyID,
	    final String passPhrase) throws PGPException,
	        NoSuchProviderException {

		PGPPrivateKey secretKey = null;

		PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

		if (pgpSecKey != null) {
			secretKey =
			    pgpSecKey.extractPrivateKey(passPhrase.toCharArray(), "BC");
		}

		return secretKey;
	}

}
