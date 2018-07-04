/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */

package com.rothsmith.encrypt.pgp;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;

/**
 * @author drothauser
 * 
 */
public final class PGPParams {

	/**
	 * PGP public key ring file containing keys for encryption.
	 */
	private String pubKeyRingFile;

	/**
	 * PGP private/secret key ring file containing keys for decryption.
	 */
	private String secKeyRingFile;

	/**
	 * The recipient (user) id of the public key used for encryption.
	 */
	private String recipient;

	/**
	 * The pass phrase.
	 */
	private String passPhrase;

	/**
	 * If true, it causes PGP to emit ciphertext or keys in ASCII Radix-64
	 * format suitable for transporting through E-mail channels.
	 */
	private boolean armored;

	/**
	 * Flag to indicate whether the output file will be "integrity protected" or
	 * not. Note that in GnuPG, encryption integrity checking is applied through
	 * the use of the --force-mdc parameter (mcd = Modification Detection Code).
	 */
	private boolean integrityCheck;

	/**
	 * @return the public key ring file containing keys for encryption.
	 */
	public String getPubKeyRingFile() {
		return pubKeyRingFile;
	}

	/**
	 * @param pubKeyRingFile
	 *            the public key ring file containing keys for encryption.
	 */
	public void setPubKeyRingFile(final String pubKeyRingFile) {
		this.pubKeyRingFile = pubKeyRingFile;
	}

	/**
	 * @param secKeyRingFile
	 *            the private/secret key ring file containing keys for
	 *            decryption.
	 */
	public void setSecKeyRingFile(final String secKeyRingFile) {
		this.secKeyRingFile = secKeyRingFile;
	}

	/**
	 * @return the private/secret key ring file containing keys for decryption.
	 */
	public String getSecKeyRingFile() {
		return secKeyRingFile;
	}

	/**
	 * @return The recipient (user) id of the public key used for encryption.
	 */
	public String getRecipient() {
		return recipient;
	}

	/**
	 * @param recipient
	 *            The recipient (user) id of the public key used for encryption.
	 */
	public void setRecipient(final String recipient) {
		this.recipient = recipient;
	}

	/**
	 * @return the passPhrase
	 */
	public String getPassPhrase() {
		return passPhrase;
	}

	/**
	 * @param passPhrase
	 *            the passPhrase to set
	 */
	public void setPassPhrase(final String passPhrase) {
		this.passPhrase = passPhrase;
	}

	/**
	 * If true, it causes PGP to emit ciphertext or keys in ASCII Radix-64
	 * format suitable for transporting through E-mail channels.
	 * 
	 * @return true for ascii armored output, else output is binary
	 */
	public boolean isArmored() {
		return armored;
	}

	/**
	 * If true, it causes PGP to emit ciphertext or keys in ASCII Radix-64
	 * format suitable for transporting through E-mail channels.
	 * 
	 * @param armored
	 *            true for ascii armored output, false for binary output
	 */
	public void setArmored(final boolean armored) {
		this.armored = armored;
	}

	/**
	 * @return the integrityCheck
	 */
	public boolean isIntegrityCheck() {
		return integrityCheck;
	}

	/**
	 * @param integrityCheck
	 *            the integrityCheck to set
	 */
	public void setIntegrityCheck(final boolean integrityCheck) {
		this.integrityCheck = integrityCheck;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String toString() {
		return ToStringBuilder.reflectionToString(this, ToStringStyle.MULTI_LINE_STYLE);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean equals(final Object obj) {
		return EqualsBuilder.reflectionEquals(this, obj);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int hashCode() {
		return HashCodeBuilder.reflectionHashCode(this);
	}

}
