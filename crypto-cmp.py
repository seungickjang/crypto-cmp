import json
import sys


def jaccard_smlt(query, document):
    intersection = set(query).intersection(set(document))
    print(set(query))
    print(set(document))
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


def main():
	if len(sys.argv) == 3:
		FileName = sys.argv[1]
		options = int(sys.argv[2])
	else:
		print("Usage: python3 jsoncmp.py [File Name] [Options]")
		print("File Name: Output filename of crypto.detector (e.g., moveit2.crypto)")
		print("Options [0 or 1]: 0 - check if matched text is identical")
		print("                  1 - check all")
		return

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
	res_db.write(json.dumps(temp['crypto_evidence'], sort_keys=True, indent=4))
	res_db.close()	
main()
#keyword_tree = objectpath.Tree()
#keyword_tuple = tuple(keyword_tree.execute('$..matched_text'))
#print(keyword_tuple)


