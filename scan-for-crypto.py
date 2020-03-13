#!/usr/bin/python3

"""
Copyright (c) 2017 Wind River Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software  distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
OR CONDITIONS OF ANY KIND, either express or implied.


Encryption Identification Scanner command line interface
"""

import sys
import json
import traceback
from cryptodetector import CryptoDetector, Output, Options, Logger, FileLister
from cryptodetector.exceptions import CryptoDetectorError


if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 4):
    print("Unsupported Python version " + str(sys.version))
    print("\nRequires Python version 3.4 or later.")
    sys.exit(1)


def jaccard_smlt(query, document):
    intersection = set(query).intersection(set(document))
    union = set(query).union(set(document))
    return len(intersection)/len(union)


def Check_with(db_name, matched_text, sentence, options = 0):
	contents = ''

	max_index = 0
	res = open(db_name,"r")
	jsonres = res.read()
	res.close()
	#print(jsonres)
	temp = json.loads(jsonres)
	if len(temp['crypto_evidence']) > 0:
		for findings in temp['crypto_evidence']:
			for hits_index in temp['crypto_evidence'][findings]['hits']:
				#print(hits_index['matched_text'])				
				if options or matched_text == hits_index['matched_text']:
					contents = hits_index['line_text_before_1']
					contents = contents + hits_index['line_text_before_2']
					contents = contents + hits_index['line_text_before_3']
					contents = contents + hits_index['line_text']
					contents = contents + hits_index['line_text_after_1']
					contents = contents + hits_index['line_text_after_2']
					contents = contents + hits_index['line_text_after_3']
					removeSpecialChars = contents.translate ({ord(c): " " for c in "!@#$%^&*()[]{};:,./<>?\|`~-=_+\n\t"})
					index = jaccard_smlt(sentence.split(" "),removeSpecialChars.split(" "))
					if (max_index < index):
						max_index = index
						max_contents = contents
	return contents, max_index


def crypto_cmp(FileName, options=0):
	jsonres = ""
	try:
		with open(FileName, "r") as input_db:
			jsonres = input_db.read()
		input_db.close()
	except IOError:
		print("File name is incorrect!")
		return
	
	res_db = open(FileName.replace(".","_") + ".json","w+")
	max_smlt = 0 
	lib_index = "Null"
	max_content = "Null"
	temp = json.loads(jsonres)
	if len(temp['crypto_evidence']) > 0:
		for findings in temp['crypto_evidence']:
			hit_nbr = 0
			for hits_index in temp['crypto_evidence'][findings]['hits']:
				matched_text = hits_index['matched_text']
				contents = hits_index['line_text_before_1']
				contents = contents + "\n" + hits_index['line_text_before_2']
				contents = contents + "\n" + hits_index['line_text_before_3']
				contents = contents + "\n" + hits_index['line_text']
				contents = contents + "\n" + hits_index['line_text_after_1']
				contents = contents + "\n" + hits_index['line_text_after_2']
				contents = contents + "\n" + hits_index['line_text_after_3']
				removeSpecialChars = contents.translate ({ord(c): " " for c in "!@#$%^&*()[]{};:,./<>?\|`~-=_+\n\t"})
				print("check: " + matched_text) 
				(libcontent, smlt) = Check_with("gnutls_db.json", matched_text, removeSpecialChars)
				if (smlt > max_smlt):
					max_smlt = smlt
					lib_index = "gnutls"
					max_content = libcontent
				#print("check_with_cryptopp...")				
				(libcontent, smlt) = Check_with("cryptopp_db.json", matched_text, removeSpecialChars)
				if (smlt > max_smlt):
					max_smlt = smlt				
					lib_index = "cryptopp"
					max_content = libcontent
				#print("check_with_libgcrypt...")
				(libcontent, smlt) = Check_with("libgcrypt_db.json", matched_text, removeSpecialChars)
				if (smlt > max_smlt):
					max_smlt = smlt
					lib_index = "libgcrypt"
					max_content = libcontent
				#print("check_with_nss...")
				(libcontent, smlt) = Check_with("nss_db.json", matched_text, removeSpecialChars)
				if (smlt > max_smlt):
					max_smlt = smlt
					lib_index = "nss"
					max_content = libcontent
				#print("check_with_openssl...")
				(libcontent, smlt) = Check_with("openssl_db.json", matched_text, removeSpecialChars)
				if (smlt > max_smlt):
					max_smlt = smlt
					lib_index = "openssl"
					max_content = libcontent
				#print("smlt: " + str(max_smlt) + " with " + str(lib_index))		
			
				
				temp['crypto_evidence'][findings]['hits'][hit_nbr]["max_similarity"] = max_smlt
				temp['crypto_evidence'][findings]['hits'][hit_nbr]["lib_index"] = lib_index
				temp['crypto_evidence'][findings]['hits'][hit_nbr]["max_content"] = max_content

				max_smlt = 0
				lib_index = "Null"
				max_content = "Null"
				hit_nbr = hit_nbr + 1
	result = json.dumps(temp['crypto_evidence'], sort_keys=True, indent=4)
	res_db.write(result)
	res_db.close()

	print(result)


if __name__ == '__main__':
	try:
		log_output_directory = None
		options = Options(CryptoDetector.VERSION).read_all_options()
		if "log" in options:
			if options["log"]:
				log_output_directory = options["output"]
		CryptoDetector(options).scan()

		print("done")

		crypto_cmp('src.crypto')
	except CryptoDetectorError as expn:
		Output.print_error(str(expn))
		if log_output_directory: Logger.write_log_files(log_output_directory)
		FileLister.cleanup_all_tmp_files()
	except KeyboardInterrupt:
		FileLister.cleanup_all_tmp_files()
		raise
	except Exception as expn:
		Output.print_error("Unhandled exception.\n\n" + str(traceback.format_exc()))
		if log_output_directory: Logger.write_log_files(log_output_directory)
		FileLister.cleanup_all_tmp_files()
