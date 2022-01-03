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
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.ExternalReference.Type;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalContact;
import org.cyclonedx.model.OrganizationalEntity;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Tool;
import org.cyclonedx.parsers.Parser;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.jacksonstore.MultiFormatStore.Format;
import org.spdx.jacksonstore.MultiFormatStore.Verbose;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.SpdxConstants;
import org.spdx.library.model.ReferenceType;
import org.spdx.library.model.SpdxCreatorInformation;
import org.spdx.library.model.SpdxDocument;
import org.spdx.library.model.SpdxElement;
import org.spdx.library.model.SpdxModelFactory;
import org.spdx.library.model.SpdxPackage;
import org.spdx.library.model.enumerations.AnnotationType;
import org.spdx.library.model.enumerations.ReferenceCategory;
import org.spdx.library.model.license.AnyLicenseInfo;
import org.spdx.library.model.license.ExtractedLicenseInfo;
import org.spdx.library.model.license.InvalidLicenseStringException;
import org.spdx.library.model.license.LicenseInfoFactory;
import org.spdx.library.model.license.ListedLicenses;
import org.spdx.library.referencetype.ListedReferenceTypes;
import org.spdx.spdxRdfStore.RdfStore;
import org.spdx.spreadsheetstore.SpreadsheetStore;
import org.spdx.spreadsheetstore.SpreadsheetStore.SpreadsheetFormatType;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.tagvaluestore.TagValueStore;

/**
 * Converts between CycloneDX and SPDX
 * Converts between SPDX and CycloneDX
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
        File outFile = new File(args[1]);
        if (outFile.exists()) {
            System.err.println("File "+args[1]+" already exists.");
            System.exit(ERROR_STATUS);
        }
        ISerializableModelStore modelStore = null;
        try {
            modelStore = fileTypeToStore(fileToFileType(outFile));
        } catch (InvalidSPDXAnalysisException e) {
            System.err.println("Unable to create SPDX model store: "+e.getMessage());
            usage();
            System.exit(ERROR_STATUS);
        } catch (com.sourceauditor.spdxcyclone.InvalidFileNameException e) {
            System.err.println(e.getMessage());
            usage();
            System.exit(ERROR_STATUS);
        }
        File inFile = new File(args[0]);
        if (!inFile.exists()) {
            System.err.println("File "+args[0]+" does not exist.");
            System.exit(ERROR_STATUS);
        }
        Bom cycloneBom = null;
        try {
            Parser cycloneParser = BomParserFactory.createParser(inFile);
            cycloneBom = cycloneParser.parse(inFile);
        } catch (ParseException e) {
            System.err.println("Error creating Cyclone parser:"+e.getMessage());
            System.exit(ERROR_STATUS);
        }
        List<String> warnings = new ArrayList<>();
        String documentUri = copyCycloneToSpdx(cycloneBom, modelStore, warnings);
        try (FileOutputStream output = new FileOutputStream(outFile)) {
            modelStore.serialize(documentUri, output);
        } catch (FileNotFoundException e) {
            System.err.println("Output file "+args[1]+" not found.");
            System.exit(ERROR_STATUS);
        } catch (IOException e) {
            System.err.println("I/O error writing output file:"+e.getMessage());
            System.exit(ERROR_STATUS);
        } catch (InvalidSPDXAnalysisException e) {
            System.err.println("SPDX error creating output file:"+e.getMessage());
            System.exit(ERROR_STATUS);
        }
        if (warnings.size() > 0) {
            System.out.println("Completed with the following warnings:");
            for (String warning:warnings) {
                System.out.println("\t"+warning);
            }
        }
    }
    
    /**
     * Copy all of the objects from cyclone to the SPDX model store
     * @param cycloneBom
     * @param spdxModelStore
     * @return SPDX Document URI created
     */
    private static String copyCycloneToSpdx(Bom cycloneBom, ISerializableModelStore spdxModelStore, List<String> warnings) {
        ModelCopyManager copyManager = new ModelCopyManager();
        String documentUri = CYCLONE_URI_PREFIX + cycloneBom.getSerialNumber() + "_version_" + cycloneBom.getSpecVersion();  //TODO: Verify this is a valid URI
        SpdxDocument spdxDoc = null;
        try {
            spdxDoc = SpdxModelFactory.createSpdxDocument(spdxModelStore, documentUri, copyManager);
        } catch (InvalidSPDXAnalysisException e) {
            System.err.println("Error creating SPDX document:"+e.getMessage());
            System.exit(ERROR_STATUS);
        }
        copyMetadata(cycloneBom.getMetadata(), cycloneBom.getSpecVersion(), spdxDoc, warnings);
        if (Objects.nonNull(cycloneBom.getExternalReferences()) && !cycloneBom.getExternalReferences().isEmpty()) {
        	for (ExternalReference er:cycloneBom.getExternalReferences()) {
        		lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - document level external reference not copied:" + 
        					er.getType() + ": " + er.getUrl());
        	}
        }
        if (Objects.nonNull(cycloneBom.getExtensibleTypes()) && !cycloneBom.getExtensibleTypes().isEmpty()) {
        	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - CycloneDX document contains extensible types which will not be copied");
        }
        if (Objects.nonNull(cycloneBom.getExtensions()) && !cycloneBom.getExtensions().isEmpty()) {
        	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - CycloneDX document contains extensions which will not be copied");
        }
        copyComponents(cycloneBom.getComponents(), spdxDoc, warnings);
        copyDependencies(cycloneBom.getDependencies(), spdxDoc, warnings);
        copyProperties(cycloneBom.getProperties(), spdxDoc, warnings);
        copyServices(cycloneBom.getServices(), spdxDoc, warnings);
        setDocumentDescribes(cycloneBom.getMetadata().getComponent(), warnings);
        // Compositions must be copied after the components
        copyCompositions(cycloneBom.getCompositions(), spdxDoc, warnings);
        return documentUri;
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
                spdxPackage.addExternalRef(spdxPackage.createExternalRef(ReferenceCategory.OTHER, 
                		new ReferenceType("http://cyclonedx.org/referenctype/distribution"), url, comment));
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
        }
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
        }
        OrganizationalEntity manufacture = metadata.getManufacture();
        if (Objects.nonNull(manufacture)) {
            StringBuilder sb = new StringBuilder("Organization: ");
            String name = manufacture.getName();
            if (Objects.nonNull(name)) {
                sb.append(name);
            } else {
                sb.append("[UNKNOWN]");
            }
            creators.add(sb.toString());
            if (Objects.nonNull(manufacture.getContacts()) && manufacture.getContacts().size() > 0) {
            	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - metadata manufacture contacts");  
            }
            if (Objects.nonNull(manufacture.getUrls()) && manufacture.getUrls().size() > 0) {
            	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - metadata manufacture urls");  
            }
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
            creators.add(sb.toString());
            if (Objects.nonNull(supplier.getContacts()) && supplier.getContacts().size() > 0) {
            	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - metadata supplier contacts");  
            }
            if (Objects.nonNull(supplier.getUrls()) && supplier.getUrls().size() > 0) {
            	lossOfFidelity(spdxDoc, warnings, "Loss of fidelity - metadata supplier urls");  
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
        //TODO: What are these properties?
        List<Property> properties = metadata.getProperties();
        if (Objects.nonNull(properties) && properties.size() > 0) {
            warnings.add("Loss of fidelity - not translating metadata properties");
        }
    }

    /**
     * Documents a loss of fidelity by adding to the warnings and annotations for the element
	 * @param spdxElement
	 * @param warnings
	 * @param msg
     * @throws InvalidSPDXAnalysisException 
	 */
	private static void lossOfFidelity(SpdxElement spdxElement,
			List<String> warnings, String msg) throws InvalidSPDXAnalysisException {
		Objects.requireNonNull(msg, "Null message for loss of fidelity");
		spdxElement.addAnnotation(spdxElement.createAnnotation("Tool: CycloneToSpdx", 
				AnnotationType.OTHER, SPDX_DATE_FORMAT.format(new Date()), msg));
		warnings.add(msg);
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
