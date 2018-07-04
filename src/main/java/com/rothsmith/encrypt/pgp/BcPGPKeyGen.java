/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;


/**
 * Class to create PGP keys for testing using BouncyCastle.
 * 
 * @version $Revision: 757 $
 * 
 * @author drothauser
 * 
 */
public class BcPGPKeyGen {

	/**
	 * PGP key size.
	 */
	private static final int KEYSIZE = 2048;

	/**
	 * Default constructor that will add the BouncyCastle security provider.
	 */
	public BcPGPKeyGen() {

		Provider provider = Security.getProvider("BC");
		if (provider == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/**
	 * Create PGP RSA type keys.
	 * 
	 * <ol>
	 * <li>Create a master key with RSA-SIGN or RSA-GENERAL algorithm.</li>
	 * <li>Create a subkey with RSA_GENERAL or RSA_ENCRYPT algorithm</li>
	 * <li>Add subkey to the master key.</li>
	 * <li>Add the keys to your key ring.</li>
	 * </ol>
	 * 
	 * @param secretOutputStream
	 *            {@link OutputStream} of the keyPair public/private key pair.
	 * @param masterOutputStream
	 *            {@link OutputStream} for the masterKey the master key pair.
	 * @param identity
	 *            identity used to identify the key
	 * @param passPhrase
	 *            pass phrase for the key
	 * @param isArmored
	 *            Enable ASCII Armor Output‎
	 */
	public void exportKeyPair(OutputStream secretOutputStream,
	    OutputStream masterOutputStream, String identity, String passPhrase,
	    boolean isArmored) {

		OutputStream publicOut = null;
		OutputStream secretOut = null;
		try {
			secretOut =
			    (isArmored) ? new ArmoredOutputStream(secretOutputStream)
			        : secretOutputStream;

			KeyPairGenerator keyPairGen =
			    KeyPairGenerator.getInstance("RSA", "BC");
			keyPairGen.initialize(KEYSIZE);
			KeyPair keyPair = keyPairGen.generateKeyPair();

			KeyPairGenerator subKeyPairGen =
			    KeyPairGenerator.getInstance("RSA", "BC");
			subKeyPairGen.initialize(KEYSIZE);
			KeyPair subkeyPair = subKeyPairGen.generateKeyPair();

			PGPKeyPair rsaKeyPair =
			    new PGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPair, new Date());

			PGPKeyPair rsaSubkeyKeyPair =
			    new PGPKeyPair(PGPPublicKey.RSA_GENERAL, subkeyPair,
			        new Date());

			String id =
			    String.format("%1$s <%1$s@fcci-group.com>", identity);

			PGPKeyRingGenerator keyRingGen =
			    new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION,
			        rsaKeyPair, id, PGPEncryptedData.AES_256,
			        passPhrase.toCharArray(), true, null, null,
			        new SecureRandom(), "BC");

			keyRingGen.addSubKey(rsaSubkeyKeyPair);
			keyRingGen.generateSecretKeyRing().encode(secretOut);
			secretOut.close();

			publicOut =
			    (isArmored) ? new ArmoredOutputStream(masterOutputStream)
			        : masterOutputStream;

			keyRingGen.generatePublicKeyRing().encode(publicOut);
		} catch (Exception e) {
			throw new PGPEncryptionException(e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(publicOut);
			IOUtils.closeQuietly(secretOut);
		}
	}

}
