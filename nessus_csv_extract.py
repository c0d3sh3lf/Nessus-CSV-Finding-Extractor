#!/usr/bin/python

import optparse, sys, re

nessus_plugin_id_regex = re.compile(r"\"\d{5,5}\"")

def read_csv(csv_file = ""):
	file_data = open(csv_file, "r").readlines()
	return file_data

def extract_findings(csv_data = []):
	filtered_findings = []
	count = 0
	for index in range(1, len(csv_data)):
		cursor = csv_data[index]
		if nessus_plugin_id_regex.match(cursor):
			risk_value = cursor.split(",")[3]
			if risk_value != '"None"':
				filtered_findings.append(cursor)
				count+=1
	return filtered_findings

def create_dict(extracted_data):
	finding_list = {}
	for index in range(0, len(extracted_data)):
		cursor = extracted_data[index]
		data_list = cursor.split(",")
		key_flag = False;
		for key in finding_list.keys():
			if data_list[7].replace("\"", "") == key:
				key_flag = True
	
		if key_flag:
			finding = finding_list[data_list[7].replace("\"", "")]
			ip_data = data_list[4].replace("\"", "") + " (" + data_list[5].upper().replace("\"", "") + "/" + data_list[6].replace("\"", "") + ")"
			ip_data_flag = False
			for ip_index in range(0, len(finding["IP"])):
				temp_ip_data = finding["IP"][ip_index]
				if temp_ip_data == ip_data:
					ip_data_flag = True

			if not ip_data_flag:
				finding["IP"].append(ip_data)

		else:
			ip_data = data_list[4].replace("\"", "") + " (" + data_list[5].upper().replace("\"", "") + "/" + data_list[6].replace("\"", "") + ")"
			finding_list[data_list[7].replace("\"", "")] = {"Severity": data_list[3].replace("\"", ""), "IP": [ip_data]}

	return finding_list

def write_to_file(finding_list = {}, output_filename = ""):
	output_file = open(output_filename, "w")
	for key in finding_list.keys():
		output_file.write(key + "\n")
		ip_list = finding_list[key]["IP"]
		for index in range(0, len(ip_list)):
			output_file.write(ip_list[index] + "\n")
		output_file.write("\n")

	print "[+] Finding list created :", output_filename

def main():
	print "Author: iNV4d3R S4M (Sumit Shrivastava)"
	print "Version: 1.0.0"
	print "Published on: 02-Sep-2015"
	parser = optparse.OptionParser()
	parser.add_option("-c", "--csv", dest="csv_file", help="Nessus CSV file")
	parser.add_option("-o", "--output-file", dest="output_file", help="Output File")
	(options, args) = parser.parse_args()
	if not options.csv_file:
		if not options.output_file:
			print "[-] Missing input and output files"
			print parser.print_help()
			sys.exit(1)
		else:
			print "[-] Missing input file"
			print parser.print_help()
			sys.exit(1)
	else:
		if not options.output_file:
			print "[-] Missing output file"
			print parser.print_help()
			sys.exit(1)
		else:
			write_to_file(create_dict(extract_findings(read_csv(options.csv_file))), options.output_file)


if __name__ == "__main__":
	main()
	
	
