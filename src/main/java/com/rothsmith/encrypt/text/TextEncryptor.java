/*
 * (c) 2012 FCCI Insurance Group All Rights Reserved.
 */
package com.rothsmith.encrypt.text;


/**
 * 
 * Interface for String encryption.
 * 
 * @version $Id: TextEncryptor.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author Doug Rothauser
 */
public interface TextEncryptor {

	/**
	 * This method encrypts a given string.
	 * 
	 * @param input
	 *            The string to encrypt
	 * @param password
	 *            The password used to generate an encryption key for encrypting
	 *            the input string.
	 * 
	 * @return Encrypted String (Base64 Encoded)
	 * 
	 */
	String encrypt(String input, String password);

	/**
	 * This method encrypts a given string.
	 * 
	 * @param input
	 *            The string to encrypt
	 * 
	 * @return Encrypted String (Base64 Encoded)
	 * 
	 */
	String encrypt(String input);

	/**
	 * This method decrypts a given string. The input string is expected to be
	 * Base64 encoded.
	 * 
	 * @param input
	 *            Encrypted string (Base64 Encoded)
	 * @param password
	 *            The password used to generate an encryption key for decrypting
	 *            the input string.
	 * 
	 * @return decrypted String
	 * 
	 */
	String decrypt(String input, String password);

	/**
	 * This method decrypts a given string. The input string is expected to be
	 * Base64 encoded.
	 * 
	 * @param input
	 *            Encrypted string (Base64 Encoded)
	 * 
	 * @return decrypted String
	 * 
	 */
	String decrypt(String input);
}