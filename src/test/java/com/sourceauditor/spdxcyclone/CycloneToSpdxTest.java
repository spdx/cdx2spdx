/**
 * SPDX-FileCopyrightText: 2022 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sourceauditor.spdxcyclone;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Gary O'Neall
 *
 */
public class CycloneToSpdxTest {
	
	static final String CDX_TEST_RESOURCES = "src/test/resources".replaceAll("/", File.separator);
	static final String VALID_BOM_PATH = CDX_TEST_RESOURCES + "/1.4/valid-bom-1.4.json".replaceAll("/", File.separator);

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * @throws java.lang.Exception
	 */
	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		fail("Not yet implemented");
	}

}
