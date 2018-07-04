/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */

package com.rothsmith.encrypt.pgp;

/**
 * Interface for PGP encryption and decryption file operations.
 * 
 * @version $Id: PGPFileCommand.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author drothauser
 * 
 */
public interface PGPFileCommand {

	/**
	 * Method that encrypts or decrypts a file.
	 * 
	 * @param inFile
	 *            the input file to encrypt or decrypt.
	 * @param outFile
	 *            the output file resulting from the cryptographic operation.
	 */
	void execute(final String inFile, final String outFile);

}