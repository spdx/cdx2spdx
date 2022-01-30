/**
 * SPDX-FileCopyrightText: 2021 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.sourceauditor.spdxcyclone;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import javax.annotation.Nullable;

import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Commit;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Composition;
import org.cyclonedx.model.Composition.Aggregate;
import org.cyclonedx.model.Copyright;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Descendants;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.ExtensibleType;
import org.cyclonedx.model.Extension;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Patch;
import org.cyclonedx.model.Pedigree;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.Swid;
import org.cyclonedx.model.Tool;
import org.cyclonedx.model.Variants;
import org.cyclonedx.parsers.Parser;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.jacksonstore.MultiFormatStore.Format;
import org.spdx.jacksonstore.MultiFormatStore.Verbose;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxConstants;
import org.spdx.library.model.Checksum;
import org.spdx.library.model.ExternalRef;
import org.spdx.library.model.ReferenceType;
import org.spdx.library.model.Relationship;
import org.spdx.library.model.SpdxCreatorInformation;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxFile;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.AnnotationType;
import org.spdx.library.model.enumerations.ChecksumAlgorithm;
import org.spdx.library.model.enumerations.FileType;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.model.license.AnyLicenseInfo;
import org.spdx.library.model.license.ConjunctiveLicenseSet;
import org.spdx.library.model.license.InvalidLicenseStringException;
import org.spdx.library.model.license.LicenseInfoFactory;
import org.spdx.library.model.license.ListedLicenses;
import org.spdx.library.model.license.SpdxNoAssertionLicense;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.spdxRdfStore.RdfStore;
import org.spdx.spreadsheetstore.SpreadsheetStore;
import org.spdx.spreadsheetstore.SpreadsheetStore.SpreadsheetFormatType;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.tagvaluestore.TagValueStore;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Converts between CycloneDX and SPDX
 * 
 * Based on the spreadsheet https://docs.google.com/spreadsheets/d/1pgpUdnucEtZ3oNcM2WYB05O6GG62vs61jPR1eKTcqR8/edit#gid=194053780
 * 
 * @author Gary O'Neall
 *
 */
public class CycloneToSpdx {
    
    static final int ERROR_STATUS = 1;
    
    static final String VERSION = "0.0.1";

    private static final String CYCLONE_URI_PREFIX = "https://cyclonedx/";
    
    static final String REFERENCE_SITE_MAVEN_CENTRAL = "http://repo1.maven.org/maven2/";
    static final String REFERENCE_SITE_NPM = "https://www.npmjs.com/";
    static final String REFERENCE_SITE_NUGET = "https://www.nuget.org/";
    static final String REFERENCE_SITE_BOWER = "http://bower.io/";
    static final SimpleDateFormat SPDX_DATE_FORMAT = new SimpleDateFormat(SpdxConstants.SPDX_DATE_FORMAT);

	private static final String INVALID_REF_REGEX = "[^0-9a-zA-Z\\.\\-\\+_]";

	private static final String NULL_SHA1_VALUE = "0000000000000000000000000000000000000000";
    
    public enum SerFileType {
        JSON, RDFXML, XML, XLS, XLSX, YAML, TAG
    }

    static Map<String, SerFileType> EXT_TO_FILETYPE;
    static {
        HashMap<String, SerFileType> temp = new HashMap<>();
        temp.put("json", SerFileType.JSON);
        temp.put("rdf.xml", SerFileType.RDFXML);
        temp.put("rdf", SerFileType.RDFXML);
        temp.put("xml", SerFileType.XML);
        temp.put("xls", SerFileType.XLS);
        temp.put("xlsx", SerFileType.XLSX);
        temp.put("yaml", SerFileType.YAML);
        temp.put("tag", SerFileType.TAG);
        temp.put("spdx", SerFileType.TAG);
        temp.put("yml", SerFileType.YAML);
        EXT_TO_FILETYPE = Collections.unmodifiableMap(temp);
    }
    
    static Map<String, ChecksumAlgorithm> CDX_ALGORITHM_TO_SPDX_ALGORITHM;
    static {
    	Map<String, ChecksumAlgorithm> algToSpdx = new HashMap<>();
//    	algToSpdx.put("", ChecksumAlgorithm.MD2); No equivalent CDX checksum
//    	algToSpdx.put("", ChecksumAlgorithm.MD4); No equivalent CDX checksum
    	algToSpdx.put("MD5", ChecksumAlgorithm.MD5);
//    	algToSpdx.put("", ChecksumAlgorithm.MD6); No equivalent CDX checksum
    	algToSpdx.put("SHA-1", ChecksumAlgorithm.SHA1);
//    	algToSpdx.put("", ChecksumAlgorithm.SHA224); No equivalent CDX checksum
    	algToSpdx.put("SHA-256", ChecksumAlgorithm.SHA256);
    	algToSpdx.put("SHA-384", ChecksumAlgorithm.SHA384);
    	algToSpdx.put("SHA-512", ChecksumAlgorithm.SHA512);
    	CDX_ALGORITHM_TO_SPDX_ALGORITHM = Collections.unmodifiableMap(algToSpdx);
    }

    /**
     * @param fileType file type for the store
     * @return the appropriate in memory based model store which supports serialization for the fileType
     * @throws InvalidSPDXAnalysisException
     */
    public static ISerializableModelStore fileTypeToStore(SerFileType fileType) throws InvalidSPDXAnalysisException {
        switch(fileType) {
        case JSON: return new MultiFormatStore(new InMemSpdxStore(), Format.JSON_PRETTY, Verbose.COMPACT);
        case RDFXML: return new RdfStore();
        case TAG: return new TagValueStore(new InMemSpdxStore());
        case XLS: return new SpreadsheetStore(new InMemSpdxStore(), SpreadsheetFormatType.XLS);
        case XLSX: return new SpreadsheetStore(new InMemSpdxStore(), SpreadsheetFormatType.XLSX);
        case XML: return new MultiFormatStore(new InMemSpdxStore(), Format.XML, Verbose.COMPACT);
        case YAML: return new MultiFormatStore(new InMemSpdxStore(), Format.YAML, Verbose.COMPACT);
        default: throw new InvalidSPDXAnalysisException("Unsupported file type: "+fileType+".  Check back later.");
        }
    }
    
    static final Gson GSON = new GsonBuilder()
            .setDateFormat(SpdxConstants.SPDX_DATE_FORMAT)	//TODO: Check to see of CycloneDX has the same format
            .create();

	private static final String MISSING_CDX_PROPERTY_STR = "MISSING_CDX_PROPERTY:";
    
    /**
     * @param file
     * @return the file type based on the file name and file extension
     * @throws InvalidFileNameException
     */
    public static SerFileType fileToFileType(File file) throws InvalidFileNameException {
        String fileName = file.getName();
        if (!fileName.contains(".")) {
            throw new InvalidFileNameException("Can not convert file to file type - no file extension");
        }
        String ext = fileName.substring(fileName.lastIndexOf(".") + 1).toLowerCase();
        if ("xml".equals(ext)) {
            if (fileName.endsWith("rdf.xml")) {
                ext = "rdf.xml";
            }
        }
        SerFileType retval = EXT_TO_FILETYPE.get(ext);
        if (Objects.isNull(retval)) {
            throw new InvalidFileNameException("Unrecognized file extension: "+ext);
        }
        return retval;
    }


    /**
     * @param args args[0] filename to convert from;  args[1] filename to convert to
     */
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Invalid number of arguments");
            usage();
            System.exit(ERROR_STATUS);
        }

        List<String> warnings = new ArrayList<>();
        try {
			cycloneDxToSpdx(args[0], args[1], warnings);
		} catch (CycloneConversionException e) {
			System.out.println(e.getMessage());
			System.exit(ERROR_STATUS);
		}
        if (warnings.size() > 0) {
            System.out.println("Completed with the following warnings:");
            for (String warning:warnings) {
                System.out.println("\t"+warning);
            }
        }
        System.exit(0);
    }
    
    /**
	 * @param cycloneDxFilePath
	 * @param spdxFilePath
	 * @param warnings
     * @throws CycloneConversionException 
	 */
	public static void cycloneDxToSpdx(String cycloneDxFilePath, String spdxFilePath, List<String> warnings) throws CycloneConversionException {
        File outFile = new File(spdxFilePath);
        if (outFile.exists()) {
        	throw new CycloneConversionException("File "+spdxFilePath+" already exists.");
        }
        try {
			if (!outFile.createNewFile()) {
				throw new CycloneConversionException("Could not create output file "+spdxFilePath);
			}
		} catch (IOException e) {
			throw new CycloneConversionException("I/O Error creating output file "+spdxFilePath, e);
		}
        ISerializableModelStore modelStore = null;
        try {
            modelStore = fileTypeToStore(fileToFileType(outFile));
        } catch (InvalidSPDXAnalysisException e) {
        	throw new CycloneConversionException("Unable to create SPDX model store: "+e.getMessage(), e);
        } catch (com.sourceauditor.spdxcyclone.InvalidFileNameException e) {
        	throw new CycloneConversionException("Cyclone DX Parsing Exception: "+e.getMessage(), e);
        }
        File inFile = new File(cycloneDxFilePath);
        if (!inFile.exists()) {
        	throw new CycloneConversionException("File "+cycloneDxFilePath+" does not exist.");
        }
        Bom cycloneBom = null;
        try {
            Parser cycloneParser = BomParserFactory.createParser(inFile);
            cycloneBom = cycloneParser.parse(inFile);
        } catch (ParseException e) {
        	throw new CycloneConversionException("Error creating Cyclone parser:"+e.getMessage());
        }
        String documentUri = null;
		try {
			documentUri = copyCycloneToSpdx(cycloneBom, modelStore, warnings);
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("SPDX Analysis exception occured while copying to SPDX model: "+e.getMessage());
		} catch (CycloneConversionException e) {
			throw new CycloneConversionException("Conversion error occured while copying to SPDX model: "+e.getMessage());
		}
        try (FileOutputStream output = new FileOutputStream(outFile)) {
            modelStore.serialize(documentUri, output);
        } catch (FileNotFoundException e) {
        	throw new CycloneConversionException("Output file "+spdxFilePath+" not found.", e);
        } catch (IOException e) {
        	throw new CycloneConversionException("I/O error writing output file:"+e.getMessage(), e);
        } catch (InvalidSPDXAnalysisException e) {
        	throw new CycloneConversionException("SPDX error creating output file:"+e.getMessage(), e);
        }
	}


	/**
     * Copy all of the objects from cyclone to the SPDX model store
     * @param cycloneBom
     * @param spdxModelStore
     * @return SPDX Document URI created
     * @throws InvalidSPDXAnalysisException 
     * @throws CycloneConversionException 
     */
    private static String copyCycloneToSpdx(Bom cycloneBom, ISerializableModelStore spdxModelStore, List<String> warnings) throws InvalidSPDXAnalysisException, CycloneConversionException {
        ModelCopyManager copyManager = new ModelCopyManager();
        String serialNumber = cycloneBom.getSerialNumber();
        if (Objects.nonNull(serialNumber)) {
        	if (serialNumber.startsWith("urn:uuid:")) {
        		serialNumber = serialNumber.substring("urn:uuid:".length());
        	}
        } else {
        	serialNumber = UUID.randomUUID().toString();
        }
        String documentUri = CYCLONE_URI_PREFIX +  serialNumber;
		documentUri = documentUri + "_" + cycloneBom.getVersion();
        SpdxDocument spdxDoc = null;
        try {
            spdxDoc = SpdxModelFactory.createSpdxDocument(spdxModelStore, documentUri, copyManager);
        } catch (InvalidSPDXAnalysisException e) {
            System.err.println("Error creating SPDX document:"+e.getMessage());
            System.exit(ERROR_STATUS);
        }
        copyMetadata(cycloneBom.getMetadata(), cycloneBom.getSpecVersion(), spdxDoc, warnings);
        if (Objects.nonNull(cycloneBom.getExternalReferences()) && !cycloneBom.getExternalReferences().isEmpty()) {
        	retainFidelity(spdxDoc, "externalReferences", cycloneBom.getExternalReferences(), warnings);
        }
        if (Objects.nonNull(cycloneBom.getExtensibleTypes()) && !cycloneBom.getExtensibleTypes().isEmpty()) {
        	retainFidelity(spdxDoc, "extensibleTypes", cycloneBom.getExtensibleTypes(), warnings);
        }
        if (Objects.nonNull(cycloneBom.getExtensions()) && !cycloneBom.getExtensions().isEmpty()) {
        	retainFidelity(spdxDoc, "extensions", cycloneBom.getExtensions(), warnings);
        }
        Map<String, SpdxElement> componentIdToSpdxElement = new HashMap<>();
        // Copy the components
        List<Component> components = cycloneBom.getComponents();
        if (Objects.nonNull(components)) {
        	for (Component component:components) {
        		componentToElement(spdxDoc, component, componentIdToSpdxElement, warnings);
        	}
        }
        copyDependencies(cycloneBom.getDependencies(), componentIdToSpdxElement, warnings);
        if (Objects.nonNull(cycloneBom.getProperties()) && !cycloneBom.getProperties().isEmpty()) {
        	retainFidelity(spdxDoc, "properties", cycloneBom.getProperties(), warnings);
        }
        List<Service> services = cycloneBom.getServices();
        if (Objects.nonNull(services) && !services.isEmpty()) {
        	retainFidelity(spdxDoc, "services", cycloneBom.getServices(), warnings);
        }
        
        if (Objects.nonNull(cycloneBom.getMetadata()) && Objects.nonNull(cycloneBom.getMetadata().getComponent())) {
        	SpdxElement describes = componentIdToSpdxElement.get(cycloneBom.getMetadata().getComponent().getBomRef());
        	if (Objects.isNull(describes) && Objects.nonNull(cycloneBom.getMetadata().getComponent())) {
        		componentToElement(spdxDoc, cycloneBom.getMetadata().getComponent(), componentIdToSpdxElement, warnings);
        		describes = componentIdToSpdxElement.get(cycloneBom.getMetadata().getComponent().getBomRef());
        		if (Objects.nonNull(describes)) {
        			componentIdToSpdxElement.put(cycloneBom.getMetadata().getComponent().getBomRef(), describes);
        			spdxDoc.getDocumentDescribes().add(describes);
        		}
        	}
        }
        // Compositions and pedigrees must be copied after the components since they refer to translated compnents
        copyCompositions(cycloneBom.getCompositions(), componentIdToSpdxElement, warnings);
        if (spdxDoc.getDocumentDescribes().isEmpty()) {
        	if (Objects.nonNull(cycloneBom.getComponents()) && !cycloneBom.getComponents().isEmpty()) {
        		// use the top level components
            	for (Component component:cycloneBom.getComponents()) {
            		spdxDoc.getDocumentDescribes().add(componentIdToSpdxElement.get(component.getBomRef()));
            	}
        	}
        	
        }
        String name = "From-Cyclone-DX";
        if (spdxDoc.getDocumentDescribes().size() == 1) {
        	name = "SBOM-for-" + spdxDoc.getDocumentDescribes().toArray(new SpdxElement[0])[0].getName().get();
        }
        spdxDoc.setName(name);
        return documentUri;
    }

	/**
	 * @param compositions compositions to be copied
	 * @param componentIdElementMap map of CDX componentID to SPDX element
	 * @param warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void copyCompositions(List<Composition> compositions,
			Map<String, SpdxElement> componentIdElementMap, 
			List<String> warnings) throws InvalidSPDXAnalysisException {
		if (Objects.isNull(compositions)) {
			return;
		}
		for (Composition composition:compositions) {
			Aggregate aggregate = composition.getAggregate();
			if (Objects.isNull(aggregate)) {
				warnings.add("Null aggregate for a composition - skipping");
				continue;
			}
			List<BomReference> assemblies = composition.getAssemblies();
			if (Objects.nonNull(assemblies)) {
				addCommentToRelationships(assemblies, aggregate.toString(), 
						RelationshipType.CONTAINS, componentIdElementMap, warnings);
			}
			List<BomReference> dependencies = composition.getDependencies();
			if (Objects.nonNull(dependencies)) {
				addCommentToRelationships(dependencies, aggregate.toString(), 
						RelationshipType.DEPENDS_ON, componentIdElementMap, warnings);
			}
		}
	}

	/**
	 * @param bomRefs List of BOM Refs for elements of the relationship type to be commented
	 * @param comment comment to add
	 * @param relationshipType Only apply to the relationship type - if null apply to all relationships
	 * @param componentIdElementMap
	 * @param warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void addCommentToRelationships(
			List<BomReference> bomRefs, String comment, @Nullable RelationshipType relationshipType,
			Map<String, SpdxElement> componentIdElementMap,
			List<String> warnings) throws InvalidSPDXAnalysisException {
		for (BomReference assembly:bomRefs) {
			String bomRef = assembly.getRef();
			if (Objects.isNull(bomRef)) {
				warnings.add("Null BOM Ref in compositions - skipping");
				continue;
			}
			SpdxElement element = componentIdElementMap.get(bomRef);
			if (Objects.isNull(element)) {
				warnings.add("The component "+bomRef+ "referenced in compositions was not found in the CycloneDX SBOM");
				continue;
			}
			for (Relationship relationship:element.getRelationships()) {
				if (Objects.nonNull(relationshipType)) {
					if (relationshipType.equals(relationship.getRelationshipType())) {
						relationship.setComment(comment);
					}
				} else {
					relationship.setComment(comment);
				}
			}
		}
	}


	/**
	 * @param dependencies dependencies to copy
	 * @param componentIdElementMap map of CDX componentID to SPDX element
	 * @param warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void copyDependencies(List<Dependency> dependencies,
			Map<String, SpdxElement> componentIdElementMap,
			List<String> warnings) throws InvalidSPDXAnalysisException {
		if (Objects.nonNull(dependencies)) {
			for (Dependency dependency:dependencies) {
				SpdxElement fromElement = componentIdElementMap.get(dependency.getRef());
				if (Objects.isNull(fromElement)) {
					warnings.add("From dependency component ref does not exist: "+dependency.getRef());
					continue;
				}
				List<Dependency> directDependencies = dependency.getDependencies();
				if (Objects.nonNull(directDependencies)) {
					for (Dependency directDependency:directDependencies) {
						if (Objects.nonNull(directDependency)) {
							SpdxElement toElement = componentIdElementMap.get(directDependency.getRef());
							if (Objects.isNull(toElement)) {
								warnings.add("To dependency component ref does not exist: "+dependency.getRef());
							} else {
								Relationship relationship = fromElement.createRelationship(toElement, RelationshipType.DEPENDS_ON, null);
								Collection<Relationship> fromRelationships = fromElement.getRelationships();
								if (!fromRelationships.contains(relationship)) {
									fromRelationships.add(relationship);
								}
							}
						}
					}
					copyDependencies(directDependencies, componentIdElementMap, warnings);
				}
 			}
		}
	}
	
	/**
	 * Add relationships representing the pedigree to the relationships for the element
	 * @param element Element to add the relationship too
	 * @param pedigree pegree to add
	 * @param componentIdElementMap map of IDs to Elements
	 * @param warnings list of warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void addPedigreeRelationships(SpdxElement element, 
			Pedigree pedigree, Map<String, SpdxElement> componentIdElementMap, 
			List<String> warnings) throws InvalidSPDXAnalysisException {
		Ancestors ancestors = pedigree.getAncestors();
		if (Objects.nonNull(ancestors) && Objects.nonNull(ancestors.getComponents())) {
			for (Component ancestor:ancestors.getComponents()) {
				if (Scope.REQUIRED.equals(componentToElement(element, ancestor, componentIdElementMap, warnings))) {
					SpdxElement ancestorElement = componentIdElementMap.get(ancestor.getBomRef());
					Relationship relationship = element.createRelationship(ancestorElement, RelationshipType.ANCESTOR_OF, null);
					element.addRelationship(relationship);
				} else {
					warnings.add("Ancestor relationship has scope other than required");
				}
			}
		}
		Descendants descendants = pedigree.getDescendants();
		if (Objects.nonNull(descendants) && Objects.nonNull(ancestors.getComponents())) {
			for (Component descendant:descendants.getComponents()) {
				if (Scope.REQUIRED.equals(componentToElement(element, descendant, componentIdElementMap, warnings))) {
					SpdxElement descendantElement = componentIdElementMap.get(descendant.getBomRef());
					Relationship relationship = element.createRelationship(descendantElement, 
							RelationshipType.DESCENDANT_OF, null);
					element.addRelationship(relationship);
				} else {
					warnings.add("Descendant relationship has scope other than required");
				}
			}
		}
		List<Commit> commits = pedigree.getCommits();
		if (Objects.nonNull(commits)) {
			retainFidelity(element, "pedigree.commits", commits, warnings);
		}
		List<Patch> patches =pedigree.getPatches();
		if (Objects.nonNull(patches)) {
			retainFidelity(element, "pedigree.patches", patches, warnings);
		}
		Variants variants = pedigree.getVariants();
		if (Objects.nonNull(variants)) {
			for (Component variant:variants.getComponents()) {
				if (Scope.REQUIRED.equals(componentToElement(element, variant, componentIdElementMap, warnings))) {
					SpdxElement variantElement = componentIdElementMap.get(variant.getBomRef());
					Relationship relationship = element.createRelationship(variantElement, 
							RelationshipType.VARIANT_OF, null);
					element.addRelationship(relationship);
				} else {
					warnings.add("Variant relationship has scope other than required");
				}
			}
		}
		String notes = pedigree.getNotes();
		if (Objects.nonNull(notes) && !notes.isBlank()) {
			retainFidelity(element, "pedigree.notes", notes, warnings);
		}
		List<ExtensibleType> extensibleTypes = pedigree.getExtensibleTypes();
		if (Objects.nonNull(extensibleTypes) && !extensibleTypes.isEmpty()) {
			retainFidelity(element, "pedigree.extensibleTypes", extensibleTypes, warnings);
		}
		Map<String, Extension> extensions = pedigree.getExtensions();
		if (Objects.nonNull(extensions) && !extensions.isEmpty()) {
			retainFidelity(element, "pedigree.extensions", extensions, warnings);
		}
	}

	/**
	 * Convert a component to an element and add it to the componentIdElementMap
	 * @param spdxDoc Document to add the element to
	 * @param component CDX Component
	 * @param componentIdElementMap map of component IDs to SpdxElement - updated in this methods
	 * @param warnings list of warnings
	 * @return the CycloneDX scope of the element
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static Scope componentToElement(SpdxElement spdxDoc,
			Component component, Map<String, SpdxElement> componentIdElementMap, List<String> warnings) throws InvalidSPDXAnalysisException {
		org.cyclonedx.model.Component.Type componentType = component.getType();
		if (Objects.isNull(componentType)) {
			warnings.add("Could not process component due to missing component type");
			return null;
		}
		SpdxElement element;
		String elementId = bomRefToSpdxId(component.getBomRef());
		if (Objects.isNull(elementId)) {
			elementId = spdxDoc.getModelStore().getNextId(IdType.SpdxId, spdxDoc.getDocumentUri());
		}
		String name = component.getName();
		if (Objects.isNull(name)) {
			warnings.add("Missing name for component");
			name = "[MISSING]";
		}

		List<Hash> hashes = component.getHashes();
		Checksum sha1 = null;
		if (Objects.nonNull(hashes)) {
			for (Hash hash:hashes) {
				if ("SHA-1".equals(hash.getAlgorithm())) {
					sha1 = spdxDoc.createChecksum(ChecksumAlgorithm.SHA1, hash.getValue());
					break;
				}
			}
		}
		if (Objects.isNull(sha1)) {
			warnings.add("Missing required SHA1 Checksum for "+name);
			sha1 = spdxDoc.createChecksum(ChecksumAlgorithm.SHA1, NULL_SHA1_VALUE);
		}
		String copyright = component.getCopyright();
		if (Objects.isNull(copyright)) {
			copyright = SpdxConstants.NOASSERTION_VALUE;
		}
		
		if (Type.FILE.equals(componentType) && !containsPackageOnlyProperties(component)) {
			element = spdxDoc.createSpdxFile(elementId, name, 
					new SpdxNoAssertionLicense(), new ArrayList<AnyLicenseInfo>(), copyright, sha1)
					.build();
			addFileProperties((SpdxFile)element, component, componentIdElementMap, warnings);
		} else {
			 element = spdxDoc.createPackage(elementId, name, new SpdxNoAssertionLicense(), copyright, new SpdxNoAssertionLicense())
					 .setFilesAnalyzed(false)
					 .build();
			 addPackageProperties((SpdxPackage)element, component, componentIdElementMap, warnings);
		}
		
		List<ExtensibleType> extensibleTypes = component.getExtensibleTypes();
		if (Objects.nonNull(extensibleTypes) && !extensibleTypes.isEmpty()) {
			retainFidelity(element, "extensibleTypes", extensibleTypes, warnings);
		}		
		Map<String, Extension> extensions = component.getExtensions();
		if (Objects.nonNull(extensions) && !extensions.isEmpty()) {
			retainFidelity(element, "extensions", extensions, warnings);
		}
		String group = component.getGroup();
		if (Objects.nonNull(group) && !group.isBlank()) {
			retainFidelity(element, "group", group, warnings);
		}
		Pedigree pedigree = component.getPedigree();
		if (Objects.nonNull(pedigree)) {
			addPedigreeRelationships(element, pedigree, componentIdElementMap, warnings);
		}
		List<Property> properties = component.getProperties();
		if (Objects.nonNull(properties) && !properties.isEmpty()) {
			retainFidelity(element, "properites", properties, warnings);
		}
		Scope scope = component.getScope();
		if (Objects.isNull(scope)) {
			scope = Scope.REQUIRED;
		}
		Swid swid = component.getSwid();
		if (Objects.nonNull(swid)) {
			retainFidelity(element, "swid", swid, warnings);
		}
		if (Objects.isNull(component.getBomRef())) {
			//NOTE: This is the only place we modify the CycloneDX BOM after parsing
			// This is needed to be able to reliably map CycloneDX components to SPDX Elements
			component.setBomRef(element.getId());
		}
		componentIdElementMap.put(component.getBomRef(), element);
		return scope;
	}

	/**
	 * Add component properties unique to the package and create annotations for any component properties the 
	 * package does not accept
	 * @param spdxPackage package to add the parameters to
	 * @param component to add the parameters to
	 * @param componentIdElementMap map of component IDs to SpdxElement - updated in this methods
	 * @param warnings list of warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void addPackageProperties(SpdxPackage spdxPackage,
			Component component, Map<String, SpdxElement> componentIdElementMap,
			List<String> warnings) throws InvalidSPDXAnalysisException {
		if (Objects.nonNull(component.getType())) {
			retainFidelity(spdxPackage, "componentType", component.getType(), warnings);
			if (Type.FILE.equals(component.getType())) {
				// Add the file as the package file name
				spdxPackage.setPackageFileName(spdxPackage.getName().get());
				// Add the package verification code for the single file package
				spdxPackage.setPackageVerificationCode(spdxPackage.createPackageVerificationCode(spdxPackage.getSha1(), new ArrayList<String>()));
			}
		}
		spdxPackage.setLicenseDeclared(listToLicenseSet(spdxPackage, convertCycloneLicenseInfo(spdxPackage, component.getLicenseChoice(), warnings)));
		List<Hash> hashes = component.getHashes();
		if (Objects.nonNull(hashes)) {
			for (Hash hash:hashes) {
				ChecksumAlgorithm algorithm = CDX_ALGORITHM_TO_SPDX_ALGORITHM.get(hash.getAlgorithm());
				if (Objects.isNull(algorithm)) {
					retainFidelity(spdxPackage, "hash", hash, warnings);
				} else {
					spdxPackage.addChecksum(spdxPackage.createChecksum(algorithm, hash.getValue()));
				}
			}
		}
		String publisher = component.getPublisher();
		String author = component.getAuthor();
		if (Objects.nonNull(publisher) && !publisher.isBlank()) {
			spdxPackage.setOriginator("Organization: "+publisher);
			if (Objects.nonNull(author) && !author.isBlank()) {
				retainFidelity(spdxPackage, "author", author, warnings);
			}
		} else if (Objects.nonNull(author) && !author.isBlank()) {
			spdxPackage.setOriginator("Person: "+author);
		}
		List<Component> subComponents = component.getComponents();
		if (Objects.nonNull(subComponents)) {
			for (Component subComponent:subComponents) {
				Scope scope = componentToElement(spdxPackage, subComponent, componentIdElementMap, warnings);
				SpdxElement subElement = componentIdElementMap.get(subComponent.getBomRef());
				if (Objects.nonNull(subElement)) {
					if (Scope.REQUIRED.equals(scope)) {
						Relationship subRelationship = spdxPackage.createRelationship(
								subElement, RelationshipType.CONTAINS, null);
						spdxPackage.addRelationship(subRelationship);
					} else if (Scope.OPTIONAL.equals(scope)) {
						Relationship subRelationship = spdxPackage.createRelationship(
								spdxPackage, RelationshipType.OPTIONAL_COMPONENT_OF, null);
						subElement.addRelationship(subRelationship);
					} else {
						warnings.add("Sub component is of excluded type: "+subComponent.getBomRef());
					}
					
				}
			}
		}
		String description = component.getDescription();
		if (Objects.nonNull(description)) {
			spdxPackage.setDescription(description);
		}
		List<ExternalReference> externalReferences = component.getExternalReferences();
		if (Objects.nonNull(externalReferences) && !externalReferences.isEmpty()) {
			copyExternalReferences(externalReferences, spdxPackage, warnings);
		}
		if (spdxPackage.getDownloadLocation().isEmpty()) {
			spdxPackage.setDownloadLocation(SpdxConstants.NOASSERTION_VALUE);
		}
		String mimeType = component.getMimeType();
		if (Objects.nonNull(mimeType)) {
			retainFidelity(spdxPackage, "mimeType", mimeType, warnings);
		}
		OrganizationalEntity supplier = component.getSupplier();
		if (Objects.nonNull(supplier) && !supplier.getName().isBlank()) {
			StringBuilder sb = new StringBuilder("Organization: ");
			sb.append(supplier.getName());
			List<OrganizationalContact> contacts = supplier.getContacts();
			String email = null;
			boolean contactFidelity = false;
			if (Objects.nonNull(contacts) && !contacts.isEmpty()) {
				for (int i = 0; i < contacts.size(); i++) {
					OrganizationalContact contact = contacts.get(i);
					
					if (Objects.nonNull(contact.getName()) && !contact.getName().isBlank() ||
							Objects.nonNull(contact.getExtensibleTypes()) && !contact.getExtensibleTypes().isEmpty() ||
							Objects.nonNull(contact.getExtensions()) && !contact.getExtensions().isEmpty()) {
						contactFidelity = true;
					}
					if (Objects.nonNull(contact.getEmail()) && !contact.getEmail().isBlank()) {
						if (Objects.isNull(email)) {
							email = contact.getEmail();
						} else {
							contactFidelity = true;
						}
					}
				}
			}
			if (Objects.nonNull(email)) {
				sb.append(" (");
				sb.append(email);
				sb.append(")");
			}
			if (contactFidelity) {
				retainFidelity(spdxPackage, "supplier.contacts", supplier.getContacts(), warnings);
			}
			if (Objects.nonNull(supplier.getUrls()) && !supplier.getUrls().isEmpty()) {
				retainFidelity(spdxPackage, "supplier.urls", supplier.getUrls(), warnings);
			}
			spdxPackage.setSupplier(sb.toString());
			warnings.add("Supplier is assumed to be an organization");
		}
		String version = component.getVersion();
		if (Objects.nonNull(version) && !version.isBlank()) {
			spdxPackage.setVersionInfo(version);
		}
		String purl = component.getPurl();
		if (Objects.nonNull(purl) && !purl.isBlank()) {
			ExternalRef purlRef = spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
					ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("purl"), 
					purl, null);
			spdxPackage.addExternalRef(purlRef);
		}
		Evidence evidence = component.getEvidence();
		if (Objects.nonNull(evidence)) {
			StringBuilder sb = new StringBuilder();
			List<Copyright> copyrights = evidence.getCopyright();
			if (Objects.nonNull(copyrights) && !copyrights.isEmpty()) {
				sb.append("Evidence copyrights: '");
				sb.append(copyrights.get(0));
				for (int i = 1; i < copyrights.size(); i++) {
					sb.append("', '");
					if (Objects.nonNull(copyrights.get(i).getText())) {
						sb.append(copyrights.get(i).getText());
					} else {
						sb.append("[NO TEXT]");
					}
				}
				sb.append("'; ");
			}
			if (Objects.nonNull(evidence.getLicenseChoice())) {
				sb.append("Evidence License: ");
				sb.append(licenseChoiceToSpdxLicense(evidence.getLicenseChoice()).toString());
				sb.append("; ");
			}
			if (Objects.nonNull(component.getModified()) && component.getModified()) {
				sb.append("This package has been modified");
			}
			if (sb.length() > 0) {
				spdxPackage.setSourceInfo(sb.toString());
			}
		} else if (Objects.nonNull(component.getModified()) && component.getModified()) {
			spdxPackage.setSourceInfo("This package has been modified");
		}
	}
	
	/**
	 * Add component properties unique to the file and create annotations for any component properties the 
	 * file does not accept
	 * @param spdxFile spdxFile to add the parameters to
	 * @param component to add the parameters to
	 * @param componentIdElementMap map of component IDs to SpdxElement - updated in this methods
	 * @param warnings list of warnings
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static void addFileProperties(SpdxFile spdxFile,
			Component component, Map<String, SpdxElement> componentIdElementMap,
			List<String> warnings) throws InvalidSPDXAnalysisException {
		spdxFile.getLicenseInfoFromFiles().addAll(convertCycloneLicenseInfo(spdxFile, component.getLicenseChoice(), warnings));
		List<Hash> hashes = component.getHashes();
		if (Objects.nonNull(hashes)) {
			for (Hash hash:hashes) {
				ChecksumAlgorithm algorithm = CDX_ALGORITHM_TO_SPDX_ALGORITHM.get(hash.getAlgorithm());
				if (Objects.isNull(algorithm)) {
					retainFidelity(spdxFile, "hash", hash, warnings);
				} else if (!ChecksumAlgorithm.SHA1.equals(algorithm)) {
					spdxFile.addChecksum(spdxFile.createChecksum(algorithm, hash.getValue()));
				}
			}
		}
		String mimeType = component.getMimeType();
		if (Objects.nonNull(mimeType)) {
			FileType fileType = mimeToFileType(mimeType);
			if (Objects.nonNull(fileType)) {
				spdxFile.addFileType(fileType);
			} else {
				retainFidelity(spdxFile, "mimeType", mimeType, warnings);
			}
		}
	}
	
	/**
	 * @param component
	 * @return true if the component contains properties only applicable to a package
	 */
	private static boolean containsPackageOnlyProperties(Component component) {
		return ((Objects.nonNull(component.getAuthor()) && !component.getAuthor().isBlank()) &&
				(Objects.nonNull(component.getDescription()) && !component.getDescription().isBlank()) &&
				(Objects.nonNull(component.getPublisher()) && !component.getPublisher().isBlank()) &&
				(Objects.nonNull(component.getPurl()) && !component.getPurl().isBlank()) &&
				(Objects.nonNull(component.getSupplier()) && !component.getSupplier().getName().isBlank()) &&
				(Objects.nonNull(component.getVersion()) && !component.getVersion().isBlank()) &&
				(Objects.nonNull(component.getPurl()) && !component.getPurl().isBlank()) &&
				(Objects.nonNull(component.getComponents()) && !component.getComponents().isEmpty()) &&
				(Objects.nonNull(component.getEvidence())) &&
				(Objects.nonNull(component.getExternalReferences()) && !component.getExternalReferences().isEmpty()));
	}


	/**
	 * Convert a Mime type to an SPDX File Type
	 * @param mimeType
	 * @return SPDX file type or null if no equivalent type is found
	 */
	private static @Nullable FileType mimeToFileType(String mimeType) {
		String[] mimeParts = mimeType.toLowerCase().trim().split("/");
		if (mimeParts.length < 2) {
			return null;
		}
		switch (mimeParts[0]) {
			case "application":
				if (mimeParts[1].startsWith("spdx+"))  {
					return FileType.SPDX;
				} else if (mimeParts[1].endsWith("+zip") || mimeParts[1].endsWith("+gzip") || 
						mimeParts[1].endsWith("+rar")) {
					return FileType.ARCHIVE;
				} else if (mimeParts[1].contains("x-bytecode")) {
					return FileType.BINARY;
				}
				switch (mimeParts[1]) {
					case "zip":
					case "gzip":
					case "rar":
					case "x-bzip":
					case "x-bzip2":
					case "vnd.rar":
					case "x-tar":
					case "x-7z-compressed":
						return FileType.ARCHIVE;
					case "java-archive": 
						return FileType.BINARY;
					case "x-sh":
						return FileType.SOURCE;
					case "octet-stream":
						return FileType.BINARY;
					default: return FileType.APPLICATION;
				}
			case "audio": return FileType.AUDIO;
			case "font": return FileType.OTHER;
			case "example": return FileType.OTHER;
			case "image": return FileType.IMAGE;
			case "message": return FileType.OTHER;
			case "model": return FileType.OTHER;
			case "multipart": return FileType.ARCHIVE;
			case "text": {
				switch (mimeParts[1]) {
					case "text/javascript":
					case "x-csharp":
					case "x-java-source":
					case "x-c":
					case "x-script.phyton":
						return FileType.SOURCE;
					default: return FileType.TEXT;
				}
			}
			case "video": return FileType.VIDEO;
			default: return FileType.OTHER;
		}
			
	}

	/**
	 * @param licenseChoice license choice to convert
	 * @param parentElement SPDX Element containing the license
	 * @param warnings
	 * @return licenses that are equivalent to the CycloneDX license info
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static List<AnyLicenseInfo> convertCycloneLicenseInfo(SpdxElement parentElement,
			LicenseChoice licenseChoice, List<String> warnings) throws InvalidSPDXAnalysisException {
		List<AnyLicenseInfo> retval = new ArrayList<>();
		if (Objects.nonNull(licenseChoice)) {	
			String expression = licenseChoice.getExpression();
			if (Objects.nonNull(expression) && !expression.isBlank()) {
				try {
					retval.add(LicenseInfoFactory.parseSPDXLicenseString(expression, 
							parentElement.getModelStore(), parentElement.getDocumentUri(), parentElement.getCopyManager()));
				} catch(InvalidLicenseStringException ex) {
					warnings.add("Invalid license expression '"+expression+"'");
				}
			} 
			List<License> licenses = licenseChoice.getLicenses();
			if (Objects.nonNull(licenses)) {
				for (License lic:licenses) {
					try {
						retval.add(LicenseInfoFactory.parseSPDXLicenseString(lic.getId(), 
								parentElement.getModelStore(), parentElement.getDocumentUri(), parentElement.getCopyManager()));
						if (Objects.nonNull(lic.getAttachmentText()) && Objects.nonNull(lic.getAttachmentText().getText()) &&
								!lic.getAttachmentText().getText().isBlank()) {
							//TODO - we may be able to create a local license in the SPDX doc to handle this case
							retainFidelity(parentElement, "licenseChoice.licenses.attachmentText", lic.getAttachmentText(), warnings);
						}
						if (Objects.nonNull(lic.getUrl()) && !lic.getUrl().isBlank()) {
							//TODO - we may be able to create a local license in the SPDX doc to handle this case
							retainFidelity(parentElement, "licenseChoice.licenses.url", lic.getUrl(), warnings);
						}
						if (Objects.nonNull(lic.getExtensibleTypes()) && !lic.getExtensibleTypes().isEmpty()) {
							retainFidelity(parentElement, "licenseChoice.licenses.extensibleTypes", lic.getExtensibleTypes(), warnings);
						}
						if (Objects.nonNull(lic.getExtensions()) && !lic.getExtensions().isEmpty()) {
							retainFidelity(parentElement, "licenseChoice.licenses.extensions", lic.getExtensions(), warnings);
						}
					} catch(InvalidLicenseStringException ex) {
						warnings.add("Invalid license id '"+lic.getId()+"'");
					}
				}
			}
		}
		return retval;
	}

	/**
	 * @param parentElement Parent element containing the licenses
	 * @param licenses
	 * @return a conjunctive license set of the licenses if there is more than one, otherwise the single license
	 * @throws InvalidSPDXAnalysisException 
	 */
	private static AnyLicenseInfo listToLicenseSet(SpdxElement parentElement,
			List<AnyLicenseInfo> licenses) throws InvalidSPDXAnalysisException {
		if (licenses.size() == 0) {
			return new SpdxNoAssertionLicense();
		}
		if (licenses.size() == 1) {
			return licenses.get(0);
		} else {
			ConjunctiveLicenseSet retval = new ConjunctiveLicenseSet(parentElement.getModelStore(), 
					parentElement.getDocumentUri(), 
					parentElement.getModelStore().getNextId(IdType.Anonymous, parentElement.getDocumentUri()),
					parentElement.getCopyManager(), true);
			retval.getMembers().addAll(licenses);
			return retval;
		}
	}

	/**
	 * Convert an CDX BOM Ref into an SPDXRef
	 * @param bomRef
	 * @return SPDX Ref in valid format
	 */
	private static @Nullable String bomRefToSpdxId(String bomRef) {
		if (Objects.isNull(bomRef)) {
			return null;
		}
		return SpdxConstants.SPDX_ELEMENT_REF_PRENUM + bomRef.replaceAll(INVALID_REF_REGEX, "-");
		//TODO: This may create a non-unique reference  - e.g. bomRef@ would equal bomRef^
	}

	private static void copyExternalReferences(List<ExternalReference> externalReferences, SpdxPackage spdxPackage,
            List<String> warnings) throws InvalidSPDXAnalysisException {
        if (Objects.isNull(externalReferences)) {
            return;
        }
        for (ExternalReference externalRef:externalReferences) {
            ExternalReference.Type type = externalRef.getType();
            String url = externalRef.getUrl();
            if (Objects.isNull(url) || Objects.isNull(type)) {
                warnings.add("Skipping empty externalReference");
                continue;
            }
            String comment = externalRef.getComment();
            switch (type) {
            case VCS:
                //TODO: Convert URL to valid locator string
                if (url.startsWith(REFERENCE_SITE_BOWER)) {
                    spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                            ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("bower"), 
                            url, comment));
                } else if (url.startsWith(REFERENCE_SITE_MAVEN_CENTRAL)) {
                    spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                            ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("maven-central"), 
                            url, comment));
                } else if (url.startsWith(REFERENCE_SITE_NPM)) {
                    spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                            ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("npm"), 
                            url, comment));
                } else if (url.startsWith(REFERENCE_SITE_NUGET)) {
                    spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                            ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("nuget"), 
                            url, comment));
                } else {
                   spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.PACKAGE_MANAGER, 
                		   new ReferenceType("http://cyclonedx.org/referenctype/other-package-manager"), url, comment));
                }
                break;
            case ISSUE_TRACKER:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/issue-tracker"), url, comment));
                break;
            case WEBSITE:
                if (spdxPackage.getHomepage().isPresent()) {
                    warnings.add("More than one home page in CycloneDX.  The following will be ignored: "+url);
                } else {
                    spdxPackage.setHomepage(url);
                }
                break;
            case ADVISORIES:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.SECURITY, 
                		new ReferenceType("http://cyclonedx.org/referenctype/advisories"), url, comment));
                break;
            case BOM:
            	spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/bom"), url, comment));
                break;
            case MAILING_LIST:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/mailing_list"), url, comment));
                break;
            case SOCIAL:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/social"), url, comment));
                break;
            case CHAT:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/chat"), url, comment));
                break;
            case DOCUMENTATION:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/documentation"), url, comment));
                break;
            case SUPPORT:
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/support"), url, comment));
                break;
            case DISTRIBUTION:
                spdxPackage.setDownloadLocation(url);
                break;
            case LICENSE:
            	spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/license"), url, comment));
                break;
            case BUILD_META:
            	spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/buildmeta"), url, comment));
                break;
            case BUILD_SYSTEM:
            	spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/buildsystem"), url, comment));
                break;
            case OTHER:
                default:
                	spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                    		new ReferenceType("http://cyclonedx.org/referenctype/other"), url, comment));
                    break;
            }
        }
    }

	/**
     * Copies all relevant metadata properties to the SPDX document
     * @param metadata
     * @param cycloneSpecVersion
     * @param spdxDoc
     * @param warnings List of any warnings
     * @throws InvalidSPDXAnalysisException 
     * @throws CycloneConversionException 
     */
    private static void copyMetadata(Metadata metadata, String cycloneSpecVersion, SpdxDocument spdxDoc, 
    		List<String> warnings) throws InvalidSPDXAnalysisException, CycloneConversionException {
        List<String> creators = new ArrayList<>();
        boolean authorFidelity = false;
        for (OrganizationalContact oc:metadata.getAuthors()) {
            StringBuilder sb = new StringBuilder("Person: ");
            String name = oc.getName();
            String email = oc.getEmail();
            if (Objects.nonNull(name)) {
                sb.append(name);
            } else {
                sb.append("[UNKNOWN]");
            }
            if (Objects.nonNull(email)) {
                sb.append(" (");
                sb.append(email);
                sb.append(")");
            }
            creators.add(sb.toString());
            if (Objects.nonNull(oc.getPhone()) && !oc.getPhone().isBlank() ||
            		Objects.nonNull(oc.getExtensibleTypes()) && !oc.getExtensibleTypes().isEmpty() ||
            		Objects.nonNull(oc.getExtensions()) && !oc.getExtensions().isEmpty()) {
            	authorFidelity = true;
            }
        }
        if (authorFidelity) {
        	retainFidelity(spdxDoc, "metadata.authors", metadata.getAuthors(), warnings);
        }
        boolean toolFidelity = false;
        for (Tool tool:metadata.getTools()) {
            StringBuilder sb = new StringBuilder("Tool: ");
            String name = tool.getName();
            String vendor = tool.getVendor();
            String version = tool.getVersion();
            if (Objects.nonNull(vendor)) {
                sb.append(vendor);
                sb.append(":");
            }
            if (Objects.nonNull(name)) {
                sb.append(name);
            } else {
                sb.append("[UNKNOWN]");
            }
            if (Objects.nonNull(version)) {
                sb.append("-");
                sb.append(version);
            }
            creators.add(sb.toString());
            if (Objects.nonNull(tool.getHashes()) && !tool.getHashes().isEmpty() ||
            		Objects.nonNull(tool.getExtensibleTypes()) && !tool.getExtensibleTypes().isEmpty() ||
            		Objects.nonNull(tool.getExtensions()) && !tool.getExtensions().isEmpty()) {
            	toolFidelity = true;
            }
        }
        if (toolFidelity) {
        	retainFidelity(spdxDoc, "metadata.tools", metadata.getTools(), warnings);
        }
        OrganizationalEntity manufacture = metadata.getManufacture();
        if (Objects.nonNull(manufacture)) {
        	retainFidelity(spdxDoc, "metadata.manufacture", manufacture, warnings);
        }
        OrganizationalEntity supplier = metadata.getSupplier();
        if (Objects.nonNull(supplier)) {
            StringBuilder sb = new StringBuilder("Organization: ");
            String name = supplier.getName();
            if (Objects.nonNull(name)) {
                sb.append(name);
            } else {
                sb.append("[UNKNOWN]");
            }
            String email = null;
            boolean contactFidelity = false;
            if (Objects.nonNull(supplier.getContacts()) && supplier.getContacts().size() > 0) {
            	for (OrganizationalContact contact:supplier.getContacts()) {
            		if (Objects.nonNull(contact.getEmail()) && !contact.getEmail().isBlank()) {
            			if (Objects.isNull(email)) {
            				email = contact.getEmail();
            			} else {
            				contactFidelity = true;
            			}
            		}
            		if (Objects.nonNull(contact.getName()) && !contact.getName().isBlank() ||
            				Objects.nonNull(contact.getPhone()) && !contact.getPhone().isBlank() ||
                    		Objects.nonNull(contact.getExtensibleTypes()) && !contact.getExtensibleTypes().isEmpty() ||
                    		Objects.nonNull(contact.getExtensions()) && !contact.getExtensions().isEmpty()) {
            			contactFidelity = true;
            		}
            	}
            }
            creators.add(sb.toString());
            if (contactFidelity) {
            	retainFidelity(spdxDoc, "metadata.supplier.contacts", supplier.getContacts(), warnings);  
            }
            if (Objects.nonNull(supplier.getUrls()) && supplier.getUrls().size() > 0) {
            	retainFidelity(spdxDoc, "metadata.supplier.urls", supplier.getUrls(), warnings);  
            }
        }
        creators.add("Tool: CycloneToSpdx-"+VERSION);
        Date timestamp = metadata.getTimestamp();
        if (Objects.isNull(timestamp)) {
            throw new CycloneConversionException("Creation timestamp missing from CycloneDX BOM Metadata");
        }
        
        SpdxCreatorInformation creatorInfo = spdxDoc.createCreationInfo(creators, SPDX_DATE_FORMAT.format(timestamp));
        if (Objects.nonNull(cycloneSpecVersion)) {
        	creatorInfo.setComment("Converted from CycloneDX spec version "+cycloneSpecVersion);
        }  else {
        	creatorInfo.setComment("Converted from CycloneDX");
        }
        creatorInfo.setLicenseListVersion(ListedLicenses.getListedLicenses().getLicenseListVersion());
        AnyLicenseInfo dataLicense;
        LicenseChoice lc = metadata.getLicenseChoice();
        if (Objects.nonNull(lc)) {
            dataLicense = licenseChoiceToSpdxLicense(lc);
        } else {
            dataLicense = ListedLicenses.getListedLicenses().getListedLicenseById(SpdxConstants.SPDX_DATA_LICENSE_ID);
        }
        spdxDoc.setDataLicense(dataLicense);
        List<Property> properties = metadata.getProperties();
        if (Objects.nonNull(properties) && properties.size() > 0) {
            retainFidelity(spdxDoc, "metadata.properties", properties, warnings);
        }
        spdxDoc.setCreationInfo(creatorInfo);
    }

    /**
     * Prevent a loss of fidelity by adding to the warnings creating an annotation with enough
     * information to recreate the CycloneDX property and value.  The annotation format is:
     * <code>MISSING_CDX_PROPERTY:[propertyName]=[propertyValue] where propertyName is the name
     * of the CycloneDX property and the value is the JSON string representation of the value
	 * @param spdxElement
	 * @param warnings
     * @throws InvalidSPDXAnalysisException 
	 */
	protected static void retainFidelity(SpdxElement spdxElement,	String cycloneDxPropertyName,
			Object cycloneDxPropertyValue, List<String> warnings) throws InvalidSPDXAnalysisException {
		Objects.requireNonNull(spdxElement, "Null SPDX element for loss of fidelity");
		Objects.requireNonNull(cycloneDxPropertyName, "Null CycloneDX property name for loss of fidelity");
		StringBuilder annotationComment = new StringBuilder(MISSING_CDX_PROPERTY_STR);
		annotationComment.append(cycloneDxPropertyName);
		annotationComment.append("=");
		if (Objects.nonNull(cycloneDxPropertyValue)) {
			annotationComment.append(GSON.toJson(cycloneDxPropertyValue));
		}
		spdxElement.addAnnotation(spdxElement.createAnnotation("Tool: CycloneToSpdx", 
				AnnotationType.OTHER, SPDX_DATE_FORMAT.format(new Date()), annotationComment.toString()));
		StringBuilder message = new StringBuilder("SPDX does not support property or property value ");
		message.append(cycloneDxPropertyName);
		message.append(" for SPDX type "+spdxElement.getType());
		message.append(".  An annotation was added to the element to capture this information.");
		warnings.add(message.toString());
	}

	/**
     * @param licenseChoice cycloneDX licenseChoice
     * @return SPDX license
     * @throws InvalidLicenseStringException
     */
    private static AnyLicenseInfo licenseChoiceToSpdxLicense(LicenseChoice licenseChoice) throws InvalidLicenseStringException {
        return LicenseInfoFactory.parseSPDXLicenseString(licenseChoice.getExpression());
        
    }

    private static void usage() {
        System.out.println("Usage:");
        System.out.println("cycloneDxFilePath spdxFilePath");
        System.out.println("\tfromFilePath - File path of the CycloneDX JSON or XML file to convert from");
        System.out.println("\ttoFilePath - output file - file extension determines the type");
        System.out.println("\tSPDX file extension must be one of json, xml, rdf.xml, rdf, spdx, or yaml");
    }

}
