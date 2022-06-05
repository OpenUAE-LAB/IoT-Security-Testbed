# brute force ftp
import subprocess,os,sys
import json

try:
	dir_path = os.path.dirname(os.path.realpath(__file__))
	parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
	sys.path.insert(0, parent_dir_path)

	from aidingScripts import generalVariables
	TestFailed = generalVariables.TestFailedToLaunch
	DeviceNotSecure= generalVariables.DeviceIsntSecure
	DeviceIsSecure= generalVariables.DeviceIsSecure
	TestNotApplicable = generalVariables.TestNotApplicable
	resultsDir = generalVariables.resultsDirWIFI
	temporaryFiles = generalVariables.temporaryFiles
	testsDir=generalVariables.testsDir	

except Exception as e:
	print(e)
	TestFailed =  "Test failed"
	DeviceNotSecure = "Vulnerable"
	DeviceIsSecure ="Not Vulnerable"
	TestNotApplicable ="Not Applicable"
	resultsDir ="results/WiFi"
	

IP= sys.argv[1]
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]


filePath =  os.path.join(temporaryFiles, IP+"_portsSummary")
with open(filePath) as fread:
	ports = fread.read()
	ports = json.loads(ports)
	found = False


	for key in ports:
		if 'ftp' in ports[key]:
			ftpPort = key
			found = True


	if not found:
		#The service wasnt found in this device
		resultsummary = TestNotApplicable
		resultsummary2 = "This device does not have FTP"    

	else:

		try:

			userNames_list_file = os.path.join(testsDir, "listUser" )
			password_list_file  = os.path.join(testsDir, "nmap.lst" )

			if os.path.exists(userNames_list_file) and os.path.exists(password_list_file):
				command="hydra -I -F -L {} -P {} -s {} ftp://{}".format(userNames_list_file, password_list_file, ftpPort, IP)
				print("Command use for bruteforce is: ",  command)
				results=subprocess.check_output(command,shell=True , stderr=subprocess.STDOUT)
				results = results.decode("utf_8")
				print("\n\nresult")
				print(results)

				credientialsFound = False # flag to track if the credentials got found
				resultsLines = results.split("\n")
				for line in resultsLines:
					if f"[{ftpPort}][ftp] host: {IP}" in line: #the line that indicate the password is found
						user = line.split("login: ")[1].split(" ")[0]
						password = line.split("password: ")[1].split(" ")[0]
						credientialsFound = True

				if credientialsFound:
					resultsummary = DeviceNotSecure
					resultsummary2 = f"The FTP credientials found is {user}:{password}"				
				else:
					resultsummary = DeviceIsSecure
					resultsummary2 = "Failed to find the credientials"		

				print(f"Test results is [{resultsummary}] - {resultsummary2}")			

			else:
				#test failed, as one of the files is not found!
				resultsummary = TestFailed
				#prepare the error message
				resultsummary2 = ""
				if not os.path.exists(userNames_list_file):
					resultsummary2 = resultsummary2 + "File {} is missing.".format(userNames_list_file)
				if not os.path.exists(password_list_file):
					resultsummary2 = resultsummary2 + "File {} is missing.".format(password_list_file)
				print(resultsummary2)


		except subprocess.CalledProcessError as e:
			print("Error happend, attempting to parse the error message")
			try:
				msg = e.output
				msg = msg.decode("utf_8")
				errorMsg = "**ERROR** " + str(msg.split("[ERROR]")[1] )
				print( errorMsg)
				resultsummary = TestFailed
				resultsummary2 = errorMsg
			except:
				print("Parsing failed, the error original message is shown below")
				print (e.output)
				resultsummary = TestFailed
				resultsummary2 = "Error in the launching the test, kindly check the resultsText area."

filePath= os.path.join(resultsDir,DeviceMAC,"FTPBruteForce_Summary" )
with open (filePath , "w") as fout: 
	fout.write(resultsummary)				
	fout.write("\n")
	fout.write(resultsummary2)

