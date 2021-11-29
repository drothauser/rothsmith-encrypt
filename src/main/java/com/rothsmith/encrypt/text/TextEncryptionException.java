/*
 * (c) 2009 Rothsmith LLC All Rights Reserved.
 */
package com.rothsmith.encrypt.text;

/**
 * Class for text encryption errors.
 * 
 * $Revision: 757 $
 * 
 * @author Doug Rothauser
 * 
 */
public class TextEncryptionException
        extends RuntimeException {
	/**
	 * serialVersionUID.
	 */
	private static final long serialVersionUID = -2409618417313497372L;

	/**
	 * Constructor for TextEncryptionException.
	 */
	public TextEncryptionException() {
		super();
	}

	/**
	 * Constructor for TextEncryptionException.
	 * 
	 * @param message
	 *            Message text explaining the exception.
	 */
	public TextEncryptionException(String message) {
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
	public TextEncryptionException(String message, Throwable e) {
		super(message, e);
	}
}
