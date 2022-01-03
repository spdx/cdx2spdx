/**
 * SPDX-FileCopyrightText: 2021 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sourceauditor.spdxcyclone;

/**
 * Exceptions related to incompatible or missing properties when converting from CycloneDx to SPDX
 * 
 * @author Gary O'Neall
 *
 */
public class CycloneConversionException extends Exception {

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    /**
     * 
     */
    public CycloneConversionException() {
        super();
    }

    /**
     * @param message
     */
    public CycloneConversionException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public CycloneConversionException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public CycloneConversionException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public CycloneConversionException(String message, Throwable cause, boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

}
