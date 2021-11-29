/*
 * (c) 2009 Rothsmith LLC All Rights Reserved.
 */
package com.rothsmith.encrypt.pgp;

/**
 * Exception class for Encryptable Errors.
 * 
 * $Id: PGPEncryptionException.java 757 2012-09-05 23:00:32Z drarch $
 * 
 * @author Doug Rothauser
 * 
 */
public class PGPEncryptionException
        extends RuntimeException {
	/**
	 * serialVersionUID.
	 */
	private static final long serialVersionUID = 7697199208883438453L;

	/**
	 * Constructor for TextEncryptionException.
	 */
	public PGPEncryptionException() {
		super();
	}

	/**
	 * Constructor for TextEncryptionException.
	 * 
	 * @param message
	 *            Message text explaining the exception.
	 */
	public PGPEncryptionException(String message) {
		super(message);
	}

	/**
	 * Constructor for TextEncryptionException.
	 * 
	 * @param message
	 *            Message text explaining the exception.
	 * @param e
	 *            root cause of this exception.
	 */
	public PGPEncryptionException(String message, Throwable e) {
		super(message, e);
	}
}
