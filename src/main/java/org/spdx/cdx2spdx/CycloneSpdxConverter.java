/**
 * SPDX-FileCopyrightText: 2022 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.spdx.cdx2spdx;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;
import java.util.UUID;

import javax.annotation.Nullable;

import org.cyclonedx.model.Ancestors;
import org.cyclonedx.model.AttachmentText;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Commit;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Composition;
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
import org.cyclonedx.model.Component.Scope;
import org.cyclonedx.model.Component.Type;
import org.cyclonedx.model.Composition.Aggregate;
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
import org.spdx.library.model.enumerations.Purpose;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.enumerations.RelationshipType;
import org.spdx.library.model.license.AnyLicenseInfo;
import org.spdx.library.model.license.ConjunctiveLicenseSet;
import org.spdx.library.model.license.ExtractedLicenseInfo;
import org.spdx.library.model.license.InvalidLicenseStringException;
import org.spdx.library.model.license.LicenseInfoFactory;
import org.spdx.library.model.license.ListedLicenses;
import org.spdx.library.model.license.SpdxNoAssertionLicense;
import org.spdx.library.model.license.SpdxNoneLicense;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * @author Gary O'Neall
 * 
 * Primary class used to convert from a CycloneDX BOM to an SPDX Document
 * 
 * The <code>convert()</code> method performs the actual conversion
 *
 */
public class CycloneSpdxConverter {
	
    private static final String CYCLONE_URI_PREFIX = "https://cyclonedx/";
    
    static final String REFERENCE_SITE_MAVEN_CENTRAL = "http://repo1.maven.org/maven2/";
    static final String REFERENCE_SITE_NPM = "https://www.npmjs.com/";
    static final String REFERENCE_SITE_NUGET = "https://www.nuget.org/";
    static final String REFERENCE_SITE_BOWER = "http://bower.io/";
    static final SimpleDateFormat SPDX_DATE_FORMAT = new SimpleDateFormat(SpdxConstants.SPDX_DATE_FORMAT);
    static {
    	SPDX_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("GMT"));
    }

	private static final String INVALID_REF_REGEX = "[^0-9a-zA-Z\\.\\-\\+]";

	private static final String NULL_SHA1_VALUE = "0000000000000000000000000000000000000000";

	private static final String MISSING_CDX_PROPERTY_STR = "MISSING_CDX_PROPERTY:";
	
    static final Gson GSON = new GsonBuilder()
            .setDateFormat(SpdxConstants.SPDX_DATE_FORMAT)	//TODO: Check to see of CycloneDX has the same format
            .create();
    
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
    	algToSpdx.put("SHA3-256", ChecksumAlgorithm.SHA3_256);
    	algToSpdx.put("SHA3-384", ChecksumAlgorithm.SHA3_384);
    	algToSpdx.put("SHA3-512", ChecksumAlgorithm.SHA3_512);
    	algToSpdx.put("BLAKE2b-256", ChecksumAlgorithm.BLAKE2b_256);
    	algToSpdx.put("BLAKE2b-384", ChecksumAlgorithm.BLAKE2b_384);
    	algToSpdx.put("BLAKE2b-512", ChecksumAlgorithm.BLAKE2b_512);
    	algToSpdx.put("BLAKE3", ChecksumAlgorithm.BLAKE3);
    	CDX_ALGORITHM_TO_SPDX_ALGORITHM = Collections.unmodifiableMap(algToSpdx);
    }
    
    static Map<Component.Type, Purpose> COMPONENT_TYPE_TO_PURPOSE;
    
    static {
    	Map<Component.Type, Purpose> compPurpose = new HashMap<>();
    	compPurpose.put(Component.Type.APPLICATION, Purpose.APPLICATION);
    	compPurpose.put(Component.Type.CONTAINER, Purpose.CONTAINER);
    	compPurpose.put(Component.Type.DEVICE, Purpose.DEVICE);
    	compPurpose.put(Component.Type.FILE, Purpose.FILE);
    	compPurpose.put(Component.Type.FIRMWARE, Purpose.FIRMWARE);
    	compPurpose.put(Component.Type.FRAMEWORK, Purpose.FRAMEWORK);
    	compPurpose.put(Component.Type.LIBRARY, Purpose.LIBRARY);
    	compPurpose.put(Component.Type.OPERATING_SYSTEM, Purpose.OPERATING_SYSTEM);
    	COMPONENT_TYPE_TO_PURPOSE = Collections.unmodifiableMap(compPurpose);
    }
    
	private Bom cycloneBom;
	private IModelStore spdxModelStore;
	private ModelCopyManager copyManager;
	private List<String> warnings = new ArrayList<>();
	private String documentUri;
	private boolean converted = false;
	private Map<String, SpdxElement> componentIdToSpdxElement = new HashMap<>();
	private Map<String, AnyLicenseInfo> cdxLicenseIdToSpdxLicense = new HashMap<>();

	/**
	 * @param cycloneBom CycloneDX input BOM 
	 * @param spdxModelStore SPDX model store to store the output
	 */
	public CycloneSpdxConverter(Bom cycloneBom, IModelStore spdxModelStore) {
		this.cycloneBom = cycloneBom;
		this.spdxModelStore = spdxModelStore;
		this.copyManager = new ModelCopyManager();
	}

	/**
	 * Perform the conversion of 
	 * @throws CycloneConversionException 
	 */
	public void convert() throws CycloneConversionException {
		checkSetConverted();
		String serialNumber = cycloneBom.getSerialNumber();
        if (Objects.nonNull(serialNumber)) {
        	if (serialNumber.startsWith("urn:uuid:")) {
        		serialNumber = serialNumber.substring("urn:uuid:".length());
        	}
        } else {
        	serialNumber = UUID.randomUUID().toString();
        }
        //TODO: Retain the "urn" format - remove the prefix
        documentUri = CYCLONE_URI_PREFIX +  serialNumber;
		documentUri = documentUri + "_" + cycloneBom.getVersion();
        SpdxDocument spdxDoc = null;
        try {
            spdxDoc = SpdxModelFactory.createSpdxDocument(spdxModelStore, documentUri, copyManager);
        } catch (InvalidSPDXAnalysisException e) {
        	throw new CycloneConversionException("Error creating SPDX document:"+e.getMessage());
        }
        try {
			copyMetadata(cycloneBom.getMetadata(), cycloneBom.getSpecVersion(), spdxDoc);
		} catch (InvalidSPDXAnalysisException | CycloneConversionException e) {
			throw new CycloneConversionException("Eror copying metadata: "+e.getMessage(), e);
		}
        if (Objects.nonNull(cycloneBom.getExternalReferences()) && !cycloneBom.getExternalReferences().isEmpty()) {
        	retainFidelity(spdxDoc, "externalReferences", cycloneBom.getExternalReferences(), warnings);
        }
        if (Objects.nonNull(cycloneBom.getExtensibleTypes()) && !cycloneBom.getExtensibleTypes().isEmpty()) {
        	retainFidelity(spdxDoc, "extensibleTypes", cycloneBom.getExtensibleTypes(), warnings);
        }
        if (Objects.nonNull(cycloneBom.getExtensions()) && !cycloneBom.getExtensions().isEmpty()) {
        	retainFidelity(spdxDoc, "extensions", cycloneBom.getExtensions(), warnings);
        }
        // Copy the components
        List<Component> components = cycloneBom.getComponents();
        if (Objects.nonNull(components)) {
        	for (Component component:components) {
        		try {
					componentToElement(spdxDoc, component);
				} catch (InvalidSPDXAnalysisException | CycloneConversionException e) {
					throw new CycloneConversionException("Error converinging a CycloneDX component to element: "+e.getMessage(), e);
				}
        	}
        }
        try {
			copyDependencies(cycloneBom.getDependencies());
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Eror copying dependencies: "+e.getMessage(), e);
		}
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
        		try {
					componentToElement(spdxDoc, cycloneBom.getMetadata().getComponent());
				} catch (InvalidSPDXAnalysisException | CycloneConversionException e) {
					throw new CycloneConversionException("Error copying component to element: "+e.getMessage(), e);
				}
        		describes = componentIdToSpdxElement.get(cycloneBom.getMetadata().getComponent().getBomRef());
        		if (Objects.nonNull(describes)) {
        			componentIdToSpdxElement.put(cycloneBom.getMetadata().getComponent().getBomRef(), describes);
        			try {
						spdxDoc.getDocumentDescribes().add(describes);
					} catch (InvalidSPDXAnalysisException e) {
						throw new CycloneConversionException("Eror adding document describes: "+e.getMessage(), e);
					}
        		}
        	}
        }
        // Compositions and pedigrees must be copied after the components since they refer to translated compnents
        try {
			copyCompositions(cycloneBom.getCompositions());
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Error copying compositions: "+e.getMessage(), e);
		}
        try {
			if (spdxDoc.getDocumentDescribes().isEmpty()) {
				if (Objects.nonNull(cycloneBom.getComponents()) && !cycloneBom.getComponents().isEmpty()) {
					// use the top level components
			    	for (Component component:cycloneBom.getComponents()) {
			    		spdxDoc.getDocumentDescribes().add(componentIdToSpdxElement.get(component.getBomRef()));
			    	}
				}
				
			}
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Error setting document describes: "+e.getMessage(), e);
		}
        String name = "From-Cyclone-DX";
        try {
			if (spdxDoc.getDocumentDescribes().size() == 1) {
				name = "SBOM-for-" + spdxDoc.getDocumentDescribes().toArray(new SpdxElement[0])[0].getName().get();
			}
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Error setting document describes name: "+e.getMessage(), e);
		}
        try {
			spdxDoc.setName(name);
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Error setting document name: "+e.getMessage(), e);
		}
	}
	
	/**
	 * Checks to see if the the BOM has already been converted and sets the converted flag
	 * @throws CycloneConversionException thrown if the BOM has already been converted
	 */
	public synchronized void checkSetConverted() throws CycloneConversionException {
		if (converted) {
			throw new CycloneConversionException("The CycloneDX BOM has already been converted");
		}
		converted = true;
	}
	
	/**
	 * @param compositions compositions to be copied
	 * @throws InvalidSPDXAnalysisException 
	 */
	private void copyCompositions(List<Composition> compositions) throws InvalidSPDXAnalysisException {
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
						RelationshipType.CONTAINS);
			}
			List<BomReference> dependencies = composition.getDependencies();
			if (Objects.nonNull(dependencies)) {
				addCommentToRelationships(dependencies, aggregate.toString(), 
						RelationshipType.DEPENDS_ON);
			}
		}
	}

	/**
	 * @param bomRefs List of BOM Refs for elements of the relationship type to be commented
	 * @param comment comment to add
	 * @param relationshipType Only apply to the relationship type - if null apply to all relationships
	 * @throws InvalidSPDXAnalysisException 
	 */
	private void addCommentToRelationships(
			List<BomReference> bomRefs, String comment, 
			@Nullable RelationshipType relationshipType) throws InvalidSPDXAnalysisException {
		for (BomReference assembly:bomRefs) {
			String bomRef = assembly.getRef();
			if (Objects.isNull(bomRef)) {
				warnings.add("Null BOM Ref in compositions - skipping");
				continue;
			}
			SpdxElement element = componentIdToSpdxElement.get(bomRef);
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
	 * @throws InvalidSPDXAnalysisException 
	 */
	private void copyDependencies(List<Dependency> dependencies) throws InvalidSPDXAnalysisException {
		if (Objects.nonNull(dependencies)) {
			for (Dependency dependency:dependencies) {
				SpdxElement fromElement = componentIdToSpdxElement.get(dependency.getRef());
				if (Objects.isNull(fromElement)) {
					warnings.add("From dependency component ref does not exist: "+dependency.getRef());
					continue;
				}
				List<Dependency> directDependencies = dependency.getDependencies();
				if (Objects.nonNull(directDependencies)) {
					for (Dependency directDependency:directDependencies) {
						if (Objects.nonNull(directDependency)) {
							SpdxElement toElement = componentIdToSpdxElement.get(directDependency.getRef());
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
					copyDependencies(directDependencies);
				}
 			}
		}
	}
	
	/**
	 * Add relationships representing the pedigree to the relationships for the element
	 * @param element Element to add the relationship too
	 * @param pedigree pedigree to add
	 * @throws InvalidSPDXAnalysisException 
	 * @throws CycloneConversionException 
	 */
	private void addPedigreeRelationships(SpdxElement element, 
			Pedigree pedigree) throws InvalidSPDXAnalysisException, CycloneConversionException {
		Ancestors ancestors = pedigree.getAncestors();
		if (Objects.nonNull(ancestors) && Objects.nonNull(ancestors.getComponents())) {
			for (Component ancestor:ancestors.getComponents()) {
				if (Scope.REQUIRED.equals(componentToElement(element, ancestor))) {
					SpdxElement ancestorElement = componentIdToSpdxElement.get(ancestor.getBomRef());
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
				if (Scope.REQUIRED.equals(componentToElement(element, descendant))) {
					SpdxElement descendantElement = componentIdToSpdxElement.get(descendant.getBomRef());
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
				if (Scope.REQUIRED.equals(componentToElement(element, variant))) {
					SpdxElement variantElement = componentIdToSpdxElement.get(variant.getBomRef());
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
	 * @return the CycloneDX scope of the element
	 * @throws InvalidSPDXAnalysisException 
	 * @throws CycloneConversionException 
	 */
	private Scope componentToElement(SpdxElement spdxDoc,
			Component component) throws InvalidSPDXAnalysisException, CycloneConversionException {
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
		
		String group = component.getGroup();
		if (Objects.nonNull(group) && !group.isBlank()) {
			name = group + ":" + name;
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
			addFileProperties((SpdxFile)element, component);
		} else {
			 element = spdxDoc.createPackage(elementId, name, new SpdxNoAssertionLicense(), copyright, new SpdxNoAssertionLicense())
					 .setFilesAnalyzed(false)
					 .setPrimaryPurpose(COMPONENT_TYPE_TO_PURPOSE.get(componentType))
					 .build();
			 addPackageProperties((SpdxPackage)element, component);
		}
		
		List<ExtensibleType> extensibleTypes = component.getExtensibleTypes();
		if (Objects.nonNull(extensibleTypes) && !extensibleTypes.isEmpty()) {
			retainFidelity(element, "extensibleTypes", extensibleTypes, warnings);
		}		
		Map<String, Extension> extensions = component.getExtensions();
		if (Objects.nonNull(extensions) && !extensions.isEmpty()) {
			retainFidelity(element, "extensions", extensions, warnings);
		}
		Pedigree pedigree = component.getPedigree();
		if (Objects.nonNull(pedigree)) {
			addPedigreeRelationships(element, pedigree);
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
		componentIdToSpdxElement.put(component.getBomRef(), element);
		return scope;
	}

	/**
	 * Add component properties unique to the package and create annotations for any component properties the 
	 * package does not accept
	 * @param spdxPackage package to add the parameters to
	 * @param component to add the parameters to
	 * @throws InvalidSPDXAnalysisException 
	 * @throws CycloneConversionException 
	 */
	private void addPackageProperties(SpdxPackage spdxPackage,
			Component component) throws InvalidSPDXAnalysisException, CycloneConversionException {
		if (Objects.nonNull(component.getType())) {
			retainFidelity(spdxPackage, "componentType", component.getType(), warnings);
			if (Type.FILE.equals(component.getType())) {
				// Add the file as the package file name
				spdxPackage.setPackageFileName(spdxPackage.getName().get());
				// Add the package verification code for the single file package
				spdxPackage.setPackageVerificationCode(spdxPackage.createPackageVerificationCode(spdxPackage.getSha1(), new ArrayList<String>()));
			}
		}
		spdxPackage.setLicenseDeclared(listToLicenseSet(spdxPackage, convertCycloneLicenseInfo(spdxPackage, component.getLicenseChoice())));
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
				Scope scope = componentToElement(spdxPackage, subComponent);
				SpdxElement subElement = componentIdToSpdxElement.get(subComponent.getBomRef());
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
			List<Copyright> copyrights = evidence.getCopyright();
			if (Objects.nonNull(copyrights) && !copyrights.isEmpty()) {
				for (Copyright copyright:copyrights) {
					String copyrightText = copyright.getText();
					if (Objects.nonNull(copyrightText) && !copyrightText.isBlank()) {
						spdxPackage.getAttributionText().add(copyrightText);
					}
				}
			}
			if (Objects.nonNull(evidence.getLicenseChoice())) {
				AnyLicenseInfo spdxLicenseEvidence = licenseChoiceToSpdxLicense(spdxPackage, evidence.getLicenseChoice());
				if (Objects.nonNull(spdxLicenseEvidence) && !(spdxLicenseEvidence instanceof SpdxNoAssertionLicense)) {
					spdxPackage.getAttributionText().add("Evidence license text for: "+spdxLicenseEvidence.toString());
				}
			}
		}
		if (Objects.nonNull(component.getModified()) && component.getModified()) {
			spdxPackage.setSourceInfo("This package has been modified");
		}
	}
	
	/**
	 * Add component properties unique to the file and create annotations for any component properties the 
	 * file does not accept
	 * @param spdxFile spdxFile to add the parameters to
	 * @param component to add the parameters to
	 * @throws InvalidSPDXAnalysisException 
	 * @throws CycloneConversionException 
	 */
	private void addFileProperties(SpdxFile spdxFile,
			Component component) throws InvalidSPDXAnalysisException, CycloneConversionException {
		spdxFile.getLicenseInfoFromFiles().addAll(convertCycloneLicenseInfo(spdxFile, component.getLicenseChoice()));
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
	private boolean containsPackageOnlyProperties(Component component) {
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
	private @Nullable FileType mimeToFileType(String mimeType) {
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
	 * @return licenses that are equivalent to the CycloneDX license info
	 * @throws InvalidSPDXAnalysisException 
	 * @throws CycloneConversionException 
	 */
	private List<AnyLicenseInfo> convertCycloneLicenseInfo(SpdxElement parentElement,
			LicenseChoice licenseChoice) throws InvalidSPDXAnalysisException, CycloneConversionException {
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
						retval.add(cdxLicenseToSpdxLicense(lic, parentElement.getModelStore(), parentElement.getDocumentUri(), parentElement.getCopyManager()));
						if (Objects.nonNull(lic.getExtensibleTypes()) && !lic.getExtensibleTypes().isEmpty()) {
							retainFidelity(parentElement, "licenseChoice.licenses.extensibleTypes", lic.getExtensibleTypes(), warnings);
						}
						if (Objects.nonNull(lic.getExtensions()) && !lic.getExtensions().isEmpty()) {
							retainFidelity(parentElement, "licenseChoice.licenses.extensions", lic.getExtensions(), warnings);
						}
					} catch(InvalidSPDXAnalysisException ex) {
						warnings.add("Invalid CDX license '"+lic.getId()+"'");
					}
				}
			}
		}
		return retval;
	}

	/**
	 * @param copyManager 
	 * @param documentUri 
	 * @param modelStore 
	 * @param lic
	 * @return
	 * @throws InvalidSPDXAnalysisException 
	 */
	private synchronized AnyLicenseInfo cdxLicenseToSpdxLicense(License cdxLicense, IModelStore modelStore, String documentUri, ModelCopyManager copyManager) throws InvalidSPDXAnalysisException {
		String id = cdxLicense.getId();
		if (Objects.isNull(id)) {
			id = cdxLicense.getName();
			warnings.add("Missing CycloneDX license ID for license name "+id);
		}
		if (ListedLicenses.getListedLicenses().isSpdxListedLicenseId(id)) {
			return ListedLicenses.getListedLicenses().getListedLicenseById(id);
		}
		if (!cdxLicenseIdToSpdxLicense.containsKey(id)) {
			// create the extracted license info
			ExtractedLicenseInfo eli = new ExtractedLicenseInfo(modelStore, documentUri, cdxLicenseIdToSpdxLicenseId(id), copyManager, true);
			AttachmentText attachmentText = cdxLicense.getAttachmentText();
			if (Objects.nonNull(attachmentText)) {
				String licenseText = attachmentText.getText();
				if (Objects.nonNull(licenseText) && !licenseText.isBlank()) {
					eli.setExtractedText(licenseText);
				}
			}
			String url = cdxLicense.getUrl();
			if (Objects.nonNull(url) && !url.isBlank()) {
				eli.getSeeAlso().add(url);
			}
			String name = cdxLicense.getName();
			if (Objects.nonNull(name) && !name.isBlank()) {
				eli.setName(name);
			}
 			cdxLicenseIdToSpdxLicense.put(id, eli);
		}
		return cdxLicenseIdToSpdxLicense.get(id);
	}

	/**
	 * @param id
	 * @return
	 */
	private String cdxLicenseIdToSpdxLicenseId(String id) {
		return SpdxConstants.NON_STD_LICENSE_ID_PRENUM + id.replaceAll(INVALID_REF_REGEX, "-");
	}

	/**
	 * @param parentElement Parent element containing the licenses
	 * @param licenses
	 * @return a conjunctive license set of the licenses if there is more than one, otherwise the single license
	 * @throws InvalidSPDXAnalysisException 
	 */
	private AnyLicenseInfo listToLicenseSet(SpdxElement parentElement,
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
                		ListedReferenceTypes.getListedReferenceTypes().getListedReferenceTypeByName("advisory"),
                		url, comment));
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
     * @throws InvalidSPDXAnalysisException 
     * @throws CycloneConversionException 
     */
    private void copyMetadata(Metadata metadata, String cycloneSpecVersion, SpdxDocument spdxDoc) throws InvalidSPDXAnalysisException, CycloneConversionException {
    	if (Objects.isNull(metadata)) {
    		return;
    	}
        List<String> creators = new ArrayList<>();
        boolean authorFidelity = false;
        List<OrganizationalContact> authors = metadata.getAuthors();
        if (Objects.nonNull(authors) && !authors.isEmpty()) {
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
        }
        if (authorFidelity) {
        	retainFidelity(spdxDoc, "metadata.authors", metadata.getAuthors(), warnings);
        }
        boolean toolFidelity = false;
        final List<Tool> tools = metadata.getTools();
        if (tools != null) {
            for (Tool tool : tools) {
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
        creators.add("Tool: CycloneToSpdx-"+CycloneToSpdx.VERSION);
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
            dataLicense = licenseChoiceToSpdxLicense(spdxDoc, lc);
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
	protected void retainFidelity(SpdxElement spdxElement,	String cycloneDxPropertyName,
			Object cycloneDxPropertyValue, List<String> warnings) throws CycloneConversionException {
		Objects.requireNonNull(spdxElement, "Null SPDX element for loss of fidelity");
		Objects.requireNonNull(cycloneDxPropertyName, "Null CycloneDX property name for loss of fidelity");
		StringBuilder annotationComment = new StringBuilder(MISSING_CDX_PROPERTY_STR);
		annotationComment.append(cycloneDxPropertyName);
		annotationComment.append("=");
		if (Objects.nonNull(cycloneDxPropertyValue)) {
			annotationComment.append(GSON.toJson(cycloneDxPropertyValue));
		}
		try {
			spdxElement.addAnnotation(spdxElement.createAnnotation("Tool: CycloneToSpdx", 
					AnnotationType.OTHER, SPDX_DATE_FORMAT.format(new Date()), annotationComment.toString()));
		} catch (InvalidSPDXAnalysisException e) {
			throw new CycloneConversionException("Error adding annotation for lost fidelity: "+e.getMessage());
		}
		StringBuilder message = new StringBuilder("SPDX does not support property or property value ");
		message.append(cycloneDxPropertyName);
		message.append(" for SPDX type "+spdxElement.getType());
		message.append(".  An annotation was added to the element to capture this information.");
		warnings.add(message.toString());
	}

	/**
	 * @param parent Parent element that the license choice will be connected to
     * @param licenseChoice cycloneDX licenseChoice
     * @return SPDX license
	 * @throws CycloneConversionException 
	 * @throws InvalidSPDXAnalysisException 
     */
    private AnyLicenseInfo licenseChoiceToSpdxLicense(SpdxElement parent, LicenseChoice licenseChoice) throws InvalidSPDXAnalysisException, CycloneConversionException {
        List<AnyLicenseInfo> licenses = convertCycloneLicenseInfo(parent, licenseChoice);
        if (licenses.size() == 1) {
        	return licenses.get(0);
        } else if (licenses.size() == 0) {
        	return new SpdxNoneLicense();
        } else {
        	return parent.createConjunctiveLicenseSet(licenses);
        }
        
    }

	/**
	 * @return the cycloneBom
	 */
	public Bom getCycloneBom() {
		return cycloneBom;
	}

	/**
	 * @return the spdxModelStore
	 */
	public IModelStore getSpdxModelStore() {
		return spdxModelStore;
	}

	/**
	 * @return the copyManager
	 */
	public ModelCopyManager getCopyManager() {
		return copyManager;
	}

	/**
	 * @return the warnings
	 */
	public List<String> getWarnings() {
		return warnings;
	}

	/**
	 * @return the documentUri
	 */
	public String getDocumentUri() {
		return documentUri;
	}

	/**
	 * @return the converted
	 */
	public boolean isConverted() {
		return converted;
	}
}
