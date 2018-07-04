/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

/**
 * Interface for PGP encrypt/decrypt file operations.
 * 
 * @version $Id: PGP.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author drothauser
 */
public interface PGP {

	/**
	 * @param inputFile
	 *            the file to encrypt
	 * @param outputFile
	 *            the resulting encrypted file
	 */
	void encrypt(final String inputFile, final String outputFile);

	/**
	 * @param inputFile
	 *            the file to decrypt
	 * @param outputFile
	 *            the resulting decrypted file
	 */
	void decrypt(final String inputFile, final String outputFile);

}