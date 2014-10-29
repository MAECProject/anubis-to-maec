#***************************************************#
#                                                   #
#      Anubis -> MAEC XML Converter Script          #
#                                                   #
# Copyright (c) 2014 - The MITRE Corporation        #
#                                                   #
#***************************************************#

#BY USING THE ANUBIS TO MAEC SCRIPT, YOU SIGNIFY YOUR ACCEPTANCE OF THE TERMS AND 
#CONDITIONS OF USE.  IF YOU DO NOT AGREE TO THESE TERMS, DO NOT USE THE ANUBIS
#TO MAEC SCRIPT.

#For more information, please refer to the LICENSE.txt file.

#Anubis Converter Script
#Copyright 2014, MITRE Corp
#v0.95 - BETA
#Updated 02/24/2014 for MAEC v4.1 and CybOX v2.1

import anubis_parser as anparser
from maec.package.package import Package
import sys
import os
import traceback
from maec.misc.options import ScriptOptions
import argparse

#Create a MAEC output file from an Anubis input file
def create_maec(inputfile, outpath, verbose_error_mode, options):

    if os.path.isfile(inputfile):    

        #Create the main parser object
        parser = anparser.parser()
        
        try:
            open_file = parser.open_file(inputfile)
            
            if not open_file:
                print('\nError: Error in parsing input file. Please check to ensure that it is valid XML and conforms to the Anbuis output schema.')
                return
            
            #Parse the file to get the actions and processes
            parser.parse_document()

            #Create the MAEC package
            package = Package()
            
            #Add the analysis
            for subject in parser.maec_subjects:
                package.add_malware_subject(subject)
                
            ##Finally, Export the results
            package.to_xml_file(outpath,
                {"https://github.com/MAECProject/anubis-to-maec":"AnubisToMAEC"})

            print "Wrote to " + outpath
            
        except Exception, err:
            print('\nError: %s\n' % str(err))
            if verbose_error_mode:
                traceback.print_exc()
    else:
        print('\nError: Input file not found or inaccessible.')
        return

#Print the usage text    
def usage():
    print USAGE_TEXT
    sys.exit(1)
    
USAGE_TEXT = """
Anubis XML Output --> MAEC XML Converter Utility
v0.95 BETA // Supports MAEC v4.1 and CybOX v2.1

Usage: python anubis_to_maec.py <special arguments> -i <input anubis xml output> -o <output maec xml file>
       OR -d <directory name>

Special arguments are as follows (all are optional):
-v : verbose error mode (prints tracebacks of any errors during execution).

"""    

def main():
    parser = argparse.ArgumentParser(description="Anubis to MAEC Translator")
    parser.add_argument("input", help="the name of the input Anubis XML file OR directory of files to translate to MAEC")
    parser.add_argument("output", help="the name of the MAEC XML file OR directory to which the output will be written")
    parser.add_argument("--verbose", "-v", help="enable verbose error output mode", action="store_true", default=False)
    parser.add_argument("--deduplicate", "-dd", help="deduplicate the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--normalize", "-n", help="normalize the MAEC output (Objects only)", action="store_true", default=False)
    parser.add_argument("--dereference", "-dr", help="dereference the MAEC output (Objects only)", action="store_true", default=False)
    args = parser.parse_args()
    
    # Build up the options instance based on the command-line input
    options = ScriptOptions()
    options.deduplicate_bundles = args.deduplicate
    options.normalize_bundles = args.normalize
    options.dereference_bundles = args.dereference

    # Test if the input is a directory or file
    if os.path.isfile(args.input):
        outfilename = args.output
        # Test if the output is a directory
        # If so, concatenate "_maec.xml" to the input filename
        # and use this as the output filename
        if os.path.isdir(args.output):
            outfilename = os.path.join(args.output, str(os.path.basename(args.input))[:-4] + "_maec.xml")
        # If we're dealing with a single file, just call create_maec()
        create_maec(args.input, outfilename, args.verbose, options)
    # If a directory was specified, perform the corresponding conversion
    elif os.path.isdir(args.input):
        # Iterate and try to parse/convert each file in the directory
        for filename in os.listdir(args.input):
            # Only handle XML files
            if str(filename)[-3:] != "xml":
                print str("Error: {0} does not appear to be an XML file. Skipping.\n").format(filename)
                continue
            outfilename = str(filename)[:-4] + "_maec.xml"
            create_maec(os.path.join(args.input, filename), os.path.join(args.output, outfilename), args.verbose, options)
    else:
        print "Input file " + args.input + " does not exist"
        
    print "Done"
    
if __name__ == "__main__":
    main()    
