/**
 * SPDX-FileCopyrightText: 2021 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.cdx2spdx;

/**
 * @author Gary O'Neall
 *
 */
public class InvalidFileNameException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public InvalidFileNameException() {
        super();
    }

    /**
     * @param message
     */
    public InvalidFileNameException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public InvalidFileNameException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public InvalidFileNameException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public InvalidFileNameException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
