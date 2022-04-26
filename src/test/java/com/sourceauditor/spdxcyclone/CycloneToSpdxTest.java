/**
 * SPDX-FileCopyrightText: 2022 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sourceauditor.spdxcyclone;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Stream;

import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.Parser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.jacksonstore.MultiFormatStore.Format;
import org.spdx.jacksonstore.MultiFormatStore.Verbose;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.Annotation;
import org.spdx.library.model.Checksum;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.ChecksumAlgorithm;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore;
import org.spdx.storage.simple.InMemSpdxStore;

/**
 * @author Gary O'Neall
 *
 */
public class CycloneToSpdxTest {
	
	static final Path CDX_TEST_RESOURCES = Paths.get("src", "test", "resources", "specification", "tools",
			"src", "test", "resources");
	static final Path VALID_BOM_PATH = Paths.get(CDX_TEST_RESOURCES.toString(), "1.4", "valid-bom-1.4.json");
	static final Path CDX_EXAMPLES = Paths.get("src", "test", "resources", "bom-examples");
	static final Path CDX_SBOM_EXAMPLES = Paths.get(CDX_EXAMPLES.toString(), "SBOM");

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
	public void testAllSbomExamples() throws CycloneConversionException, IOException, InvalidSPDXAnalysisException {
		// Test all the SBOM examples to see if any don't verify
		try (Stream<Path> paths = Files.walk(CDX_SBOM_EXAMPLES)) {
			paths.filter(Files::isRegularFile).forEach(path -> {
				File f = path.toFile();
				if (f.getName().endsWith(".json")) {
					Parser cycloneParser;
					try {
						cycloneParser = BomParserFactory.createParser(f);
						Bom cycloneBom = cycloneParser.parse(f);
						List<String> warnings = new ArrayList<>();
						IModelStore store = new InMemSpdxStore();
						ModelCopyManager copyManager = new ModelCopyManager();
						try {
							String docUri = CycloneToSpdx.copyCycloneToSpdx(cycloneBom, store, warnings);
							SpdxDocument doc = SpdxModelFactory.createSpdxDocument(store, docUri, copyManager);
							List<String> verify = doc.verify();
							if (!verify.isEmpty()) {
								fail("SBOM "+path.getFileName()+" has "+verify.size()+" verification errors.");
							}
						} catch (InvalidSPDXAnalysisException
								| CycloneConversionException e) {
							fail("Conversion exception for SBOM "+path.getFileName()+": "+e.getMessage());
						}
					} catch (ParseException e) {
						fail("Parse exception for SBOM "+path.getFileName()+": "+e.getMessage());
					}
		            
				}
	            
			});
		}
	}

	@Test
	public void testValidSbomV1dot4() throws CycloneConversionException, IOException, InvalidSPDXAnalysisException {
		List<String> warnings = new ArrayList<>();
		File resultDirectory = Files.createTempDirectory("cdxTest").toFile();
		try {
			String resultFilePath = resultDirectory + File.separator + "resultSpdx.json";
			CycloneToSpdx.cycloneDxToSpdx(VALID_BOM_PATH.toString(), resultFilePath, warnings);
			MultiFormatStore store = new MultiFormatStore(new InMemSpdxStore(), Format.JSON_PRETTY, Verbose.COMPACT);
			String documentUri;
			try (InputStream is = new FileInputStream(new File(resultFilePath))) {
				documentUri = store.deSerialize(is, false);
			}
			SpdxDocument spdxDoc = new SpdxDocument(store, documentUri, null, false);
			List<String> verify = spdxDoc.verify();
			assertEquals(0, verify.size());
			List<String> expectedDocAttributionPatterns = new ArrayList<>();
			assertTrue(spdxDoc.getDocumentUri().contains("3e671687-395b-41f5-a30f-a58921a69b79"));
			assertTrue(spdxDoc.getDocumentUri().endsWith("_1"));
			//TODO: Put in the actual full time once the issue with converting to local time is resolved
			//  See issue #1
			assertTrue(spdxDoc.getCreationInfo().getCreated().startsWith("2020-04-13"));
			Collection<String> creators = spdxDoc.getCreationInfo().getCreators();
			boolean foundTool = false;
			boolean foundPerson = false;
			boolean foundOrganization = false;
			for (String creator:creators) {
				if (creator.contains("Awesome Tool")) {
					assertFalse(foundTool);
					foundTool = true;
					assertTrue(creator.startsWith("Tool:"));
					assertTrue(creator.contains("9.1.2"));
					// Too checksums
					expectedDocAttributionPatterns.add("25ed8e31b995bb927966616df2a42b979a2717f0");
					expectedDocAttributionPatterns.add("a74f733635a19aefb1f73e5947cef59cd7440c6952ef0f03d09d974274cbd6df");
				}
				if (creator.contains("Samantha Wright")) {
					assertFalse(foundPerson);
					foundPerson = true;
					assertTrue(creator.startsWith("Person:"));
					assertTrue(creator.contains("(samantha.wright@example.com)"));
					expectedDocAttributionPatterns.add("800-555-1212");
				}
				if (creator.contains("Acme, Inc.")) {
					assertFalse(foundOrganization);
					foundOrganization = true;
					assertTrue(creator.startsWith("Organization: "));
					expectedDocAttributionPatterns.add("https://example.com");
					expectedDocAttributionPatterns.add("Acme Distribution");
					expectedDocAttributionPatterns.add("distribution@example.com");
				}
			}
			assertTrue(foundTool);
			assertTrue(foundPerson);
			assertTrue(foundOrganization);
			expectedDocAttributionPatterns.add("Acme, Inc.");
			expectedDocAttributionPatterns.add("Acme Professional Services");
			expectedDocAttributionPatterns.add("professional.services@example.com");
			assertEquals(1, spdxDoc.getDocumentDescribes().size());
			SpdxElement described = spdxDoc.getDocumentDescribes().toArray(new SpdxElement[1])[0];
			assertEquals("Acme Application", described.getName().get());
			assertTrue(spdxDoc.getName().get().contains("Acme Application"));
			assertAnnotationsContains(spdxDoc.getAnnotations(), expectedDocAttributionPatterns);
			
			// check on all the packages
			final List<String> foundComponentNames = new ArrayList<>();
			SpdxModelFactory.getElements(spdxDoc.getModelStore(), spdxDoc.getDocumentUri(), 
					spdxDoc.getCopyManager(), SpdxPackage.class).forEach(element -> {
						try {
							SpdxPackage pkg = (SpdxPackage)element;
							foundComponentNames.add(pkg.getName().get());
							if ("Acme Application".equals(pkg.getName().get())) {
								List<String> expectedAnnotations = new ArrayList<>();
								expectedAnnotations.add("application".toUpperCase());	// type
								assertEquals("Person: Acme Super Heros", pkg.getOriginator().get());
								/** TODO: Uncomment this out once the SWID external refs are implemented
								assertEquals("9.1.1", pkg.getVersionInfo().get());
								ExternalRef[] externalRefs = pkg.getExternalRefs().toArray(new ExternalRef[pkg.getExternalRefs().size()]);
								assertEquals(1, externalRefs.length);
								assertEquals(ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("swid"), externalRefs[0].getReferenceType());
								assertEquals(ReferenceCategory.SECURITY, externalRefs[0].getReferenceCategory());
								assertTrue(externalRefs[0].getReferenceLocator().contains("swidgen-242eb18a-503e-ca37-393b-cf156ef09691_9.1.1"));
								**/
								expectedAnnotations.add("PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiID8"); // part of the SWID content
								assertAnnotationsContains(pkg.getAnnotations(), expectedAnnotations);
							} else if ("tomcat-catalina".equals(pkg.getName().get())) {
								List<String> expectedAnnotations = new ArrayList<>();
								expectedAnnotations.add("library".toUpperCase());	// type
								assertTrue(pkg.getOriginator().get().contains("Acme Inc"));
								expectedAnnotations.add("com.acme"); // group
								assertEquals("9.0.14", pkg.getVersionInfo().get());
								if (pkg.getId().contains("npm")) {
									// There are 3 in the BOM test file with the same name - one has more details
									assertEquals("e6b1000b94e835ffd37f4c6dcbdad43f4b48a02a", pkg.getSha1());
									boolean foundSha1 = false;
									boolean foundSha512 = false;
									boolean foundSha256 = false;
									boolean foundMd5 = false;
									for (Checksum checksum:pkg.getChecksums()) {
										if (ChecksumAlgorithm.SHA1.equals(checksum.getAlgorithm())) {
											assertFalse(foundSha1);
											foundSha1 = true;
											assertEquals("e6b1000b94e835ffd37f4c6dcbdad43f4b48a02a", checksum.getValue());
										} else if (ChecksumAlgorithm.SHA256.equals(checksum.getAlgorithm())) {
											assertFalse(foundSha256);
											foundSha256 = true;
											assertEquals("f498a8ff2dd007e29c2074f5e4b01a9a01775c3ff3aeaf6906ea503bc5791b7b", checksum.getValue());
										} else if (ChecksumAlgorithm.SHA512.equals(checksum.getAlgorithm())) {
											assertFalse(foundSha512);
											foundSha512 = true;
											assertEquals("e8f33e424f3f4ed6db76a482fde1a5298970e442c531729119e37991884bdffab4f9426b7ee11fccd074eeda0634d71697d6f88a460dce0ac8d627a29f7d1282",
													checksum.getValue());
										} else if (ChecksumAlgorithm.MD5.equals(checksum.getAlgorithm())) {
											assertFalse(foundMd5);
											foundMd5 = true;
											assertEquals("3942447fac867ae5cdb3229b658f4d48",
													checksum.getValue());
										} else {
											fail("Unexpected checksum algorithm");
										}
									}
									assertTrue(foundSha512);
									assertTrue(foundSha256);
									assertTrue(foundSha1);
									assertTrue(foundMd5);
									assertEquals("Apache-2.0", pkg.getLicenseDeclared().toString());
									expectedAnnotations.add("text/plain");
									expectedAnnotations.add("base64");
									expectedAnnotations.add("License text here");
									expectedAnnotations.add("https://www.apache.org/licenses/LICENSE-2.0.txt");
									ExternalRef[] externalRefs = pkg.getExternalRefs().toArray(new ExternalRef[pkg.getExternalRefs().size()]);
									assertEquals(1, externalRefs.length);
									assertEquals(ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), externalRefs[0].getReferenceType());
									assertEquals(ReferenceCategory.PACKAGE_MANAGER, externalRefs[0].getReferenceCategory());
									assertEquals("pkg:npm/acme/component@1.0.0", externalRefs[0].getReferenceLocator());
									Relationship[] relationships = pkg.getRelationships().toArray(new Relationship[pkg.getRelationships().size()]);
									assertEquals(3, relationships.length);
									int numAcestors = 0;
									int numDependencies = 0;
									for (Relationship relationship:relationships) {
										SpdxPackage relatedPackage = (SpdxPackage)relationship.getRelatedSpdxElement().get();
										assertEquals("tomcat-catalina", relatedPackage.getName().get());
										
										assertEquals("9.0.14", relatedPackage.getVersionInfo().get());
										if (RelationshipType.ANCESTOR_OF.equals(relationship.getRelationshipType())) {
											numAcestors++;
										} else if (RelationshipType.DEPENDS_ON.equals(relationship.getRelationshipType())) {
											numDependencies++;
										} else {
											fail("Unexpected relationship type: "+relationship.getRelationshipType());
										}
									}
									assertEquals(2, numAcestors);
									assertEquals(1, numDependencies);
									expectedAnnotations.add("123"); // commit
									expectedAnnotations.add("2018-11-13T"); // commit
								}
								assertAnnotationsContains(pkg.getAnnotations(), expectedAnnotations);
							} else if ("mylibrary".equals(pkg.getName().get())) {
								List<String> expectedAnnotations = new ArrayList<>();
								assertTrue(pkg.getSupplier().get().contains("Example, Inc."));
								assertTrue(pkg.getSupplier().get().contains("support@example.com"));
								expectedAnnotations.add("800-555-1212");
								expectedAnnotations.add("Example Support APAC");
								expectedAnnotations.add("support@apac.example.com");
								assertEquals("Person: Example Super Heros", pkg.getOriginator().get());
								expectedAnnotations.add("https://example.com");
								expectedAnnotations.add("https://example.net");
								expectedAnnotations.add("org.example");
								assertEquals("1.0.0", pkg.getVersionInfo().get());
								assertAnnotationsContains(pkg.getAnnotations(), expectedAnnotations);
							} else {
								fail("Unexpected package "+pkg.getName().get());
							}
						} catch (Exception ex) {
							fail("Exception occurred while processing packages: "+ex.getMessage());
						}
					});
			assertEquals(5, foundComponentNames.size());
			assertTrue(foundComponentNames.contains("Acme Application"));
			assertTrue(foundComponentNames.contains("tomcat-catalina"));
			assertTrue(foundComponentNames.contains("mylibrary"));
		} finally {
			deleteDirOrFile(resultDirectory);
		}
	}

	/**
	 * @param annotations
	 * @param expectedContainedStrings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private void assertAnnotationsContains(Collection<Annotation> annotations,
			List<String> expectedContainedStrings) throws InvalidSPDXAnalysisException {
		boolean[] foundContainedString = new boolean[expectedContainedStrings.size()];
		for (Annotation annotation:annotations) {
			for (int i = 0; i < expectedContainedStrings.size(); i++) {
				if (annotation.getComment().contains(expectedContainedStrings.get(i))) {
					foundContainedString[i] = true;
				}
			}
		}
		for (int i = 0; i < expectedContainedStrings.size(); i++) {
			if (!foundContainedString[i]) {
				fail("Did not find annotation containing "+expectedContainedStrings.get(i));
			}
		}
	}

	/**
	 * @param f
	 */
	private static void deleteDirOrFile(File f) {
		if (f.isDirectory()) {
			for (File subFile:f.listFiles()) {
				deleteDirOrFile(subFile);
			}
		}
		assertTrue(f.delete());
	}

    static final Path CDX_BOMS = Paths.get("src", "test", "resources", "cdxboms");

    @Test
    public void testMetadataToolsEmpty() throws ParseException, CycloneConversionException, InvalidSPDXAnalysisException {
        final File emptyToolsBom = new File(Paths.get(CDX_BOMS.toString(), "empty-tools").toFile(), "empty-tools.sbom.json");

	final Bom cycloneBom = BomParserFactory.createParser(emptyToolsBom).parse(emptyToolsBom);

	final IModelStore store = new InMemSpdxStore();
	final String docUri = CycloneToSpdx.copyCycloneToSpdx(cycloneBom, store, new ArrayList<>());

	final SpdxDocument doc = SpdxModelFactory.createSpdxDocument(store, docUri, new ModelCopyManager());
        final List<String> verify = doc.verify();
	assertTrue(verify.toString(), verify.isEmpty());
    }
}
