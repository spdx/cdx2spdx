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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;


import org.cyclonedx.BomParserFactory;
import org.cyclonedx.exception.ParseException;
import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.Parser;
import org.spdx.jacksonstore.MultiFormatStore;
import org.spdx.jacksonstore.MultiFormatStore.Format;
import org.spdx.jacksonstore.MultiFormatStore.Verbose;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.spdxRdfStore.RdfStore;
import org.spdx.spreadsheetstore.SpreadsheetStore;
import org.spdx.spreadsheetstore.SpreadsheetStore.SpreadsheetFormatType;
import org.spdx.storage.ISerializableModelStore;
import org.spdx.storage.simple.InMemSpdxStore;
import org.spdx.tagvaluestore.TagValueStore;

/**
 * Converts between CycloneDX and SPDX
 * 
 * Based on the spreadsheet https://docs.google.com/spreadsheets/d/1PIiSYLJHlt8djG5OoOYniy_I-J31UMhBKQ62UUBHKVA/edit?usp=sharing
 * 
 * @author Gary O'Neall
 *
 */
public class CycloneToSpdx {
    
    static final int ERROR_STATUS = 1;
    
    static final String VERSION = "0.0.2";
    
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

        List<String> warnings = new ArrayList<>();
        try {
        	warnings = cycloneDxToSpdx(args[0], args[1]);
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
	public static List<String> cycloneDxToSpdx(String cycloneDxFilePath, String spdxFilePath) throws CycloneConversionException {
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
        CycloneSpdxConverter converter = new CycloneSpdxConverter(cycloneBom, modelStore);
		converter.convert();
        try (FileOutputStream output = new FileOutputStream(outFile)) {
            modelStore.serialize(converter.getDocumentUri(), output);
            return converter.getWarnings();
        } catch (FileNotFoundException e) {
        	throw new CycloneConversionException("Output file "+spdxFilePath+" not found.", e);
        } catch (IOException e) {
        	throw new CycloneConversionException("I/O error writing output file:"+e.getMessage(), e);
        } catch (InvalidSPDXAnalysisException e) {
        	throw new CycloneConversionException("SPDX error creating output file:"+e.getMessage(), e);
        }
	}

    private static void usage() {
        System.out.println("Usage:");
        System.out.println("cycloneDxFilePath spdxFilePath");
        System.out.println("\tfromFilePath - File path of the CycloneDX JSON or XML file to convert from");
        System.out.println("\ttoFilePath - output file - file extension determines the type");
        System.out.println("\tSPDX file extension must be one of json, xml, rdf.xml, rdf, spdx, or yaml");
    }

}
