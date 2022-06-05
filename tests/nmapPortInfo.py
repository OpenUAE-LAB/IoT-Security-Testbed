#Check ports and get infro
#7/1/2019

import subprocess,os,sys
import nmap
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
	

DeviceIP= sys.argv[1]
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]

def checkVersionInJson(DeviceIP, port, jsonFile):
	#First it will retrieve the name of the service on that port.
	Product = nm['tcp'][port]['product']
	versionResult = TestFailed
	versionResult2= "[Prt:{}] ".format(port) 

	print(len(Product))
	#If the name is not empty then the test will carry on.
	if (len(Product)):
		print("Product: ", Product)
		Version = nm['tcp'][port]['version']

		if(Version):
			print("[Nmap port info test]: Port [{}] has product [{}] with version [{}]".format(port, Product,  Version))
			
			#Remove extra words in the Version name such as "or later"
			if ("or later"  in Version):
				Version=Version.split(" or")[0]
			else:
				Version=Version

			#check if out-dated
			try:#open DB
				jsonFile = os.path.join(testsDir, jsonFile)
				with open(jsonFile) as json_data:
					data = json.load(json_data)
					keyfound = False
					latest=None
					for i in data.keys():
						#if the device's service verison has been found here
						#Save the version found in the database as latest one available
						#then compare it with the current one from the device under test
						
						if (Product.lower() in i.lower() or i.lower() in Product.lower()):
							latest=data[i]['Version']
							break #exit the loop
					
					#If no latest found, then the test assumes that the current
					#version found in the device is the latest one.
					if latest == None:
						latest=data[Product]['Version']
				#call the device's service version as current version.
				current=Version
				
				#Get Current and latest version, split "3.2.1" to an array[3,2,1]
				current=current.split(".")
				latest=latest.split(".")
				iteration = len(latest) 
				if (len(current)<len(latest)):
						iteration = len(current) 
					
				resultisOld = False
				versionResult=DeviceIsSecure
				versionResult2 = "[Prt:{}|Srv:{}] The version is updated accourding the the DB".format(port, Product) 
				for i in range(0,iteration):
					#Check if the current Version is the older..
					if(current[i] < latest[i]):
						resultisOld=True
						versionResult2 = "[Prt:{}|Srv:{}] The version is old".format(port, Product)  
						versionResult = DeviceNotSecure
						break		
			except Exception as e:
				print("[Nmap port info test]: Error: ", str(e))
				versionResult= TestFailed
				versionResult2= "[Prt:{}|Srv:{}]Error - {}".format(port, Product, str(e) )
				pass

		else:
			#the device's version isnt mentioned
			versionResult = TestNotApplicable
			versionResult2 ="[Prt:{}|Srv:{}] The service version is not mentioned".format(port, Product) 

	else:
		
		versionResult= TestNotApplicable
		versionResult2 = "[Prt:{}] The device did not reveal the product running that port".format(port)

	print("[Nmap port info test]: Checking date the service [{}] on port: [{}] The result is: [{}]".format(Product, port,  versionResult)) 
	return versionResult, versionResult2
	
	
#check if has vulnerabilities 
def checkVulnerbilityVersion(DeviceIP, port, Dev):
	results= TestFailed #by default..unless different 
	results2="Error occured"
	resultsDetials={}
	command="..."
	
	#First it will retrieve the name of the service on that port.
	Product = Dev['product']
	
	textToCheck = ""
	if (Product != ""): #name is not empty
		textToCheck = textToCheck+Product
		Version = Dev['version']
		if ("or later"  in Version): #Version text need parsing 
			Version=Version.split(" or")[0]
				
		commands = textToCheck+" "+Version
		#print("[Nmap port info test]: Checking exploits of port: {} that has {}".format(str(port), Product ))
		
		##start chcking the exploits
		command="searchsploit -t -j " + commands

		try:
			TestResults=subprocess.check_output(command,shell=True,stderr=open(os.devnull, 'w'))
			resultsJson = json.loads(TestResults)
			
			if "RESULTS_EXPLOIT"  in resultsJson:
				if len(resultsJson["RESULTS_EXPLOIT"]) == 0: #no results found
					results = DeviceIsSecure #so far it is secure as no exp found
					results2="[Prt:{}|Srv:{}] No exploites found for command:{} ".format(port, Product,commands) #just as place holder
					try:
						#if no result found .. Do seach again in different way..
						#search by the service name and the first part of the version. 
						commands=textToCheck+" "+Version.split(".")[0]
						command="searchsploit -t -j " + commands
						
						TestResults=subprocess.check_output(command,shell=True,stderr=open(os.devnull, 'w'))
						resultsJson = json.loads(TestResults)
						if "RESULTS_EXPLOIT"  in resultsJson:
							if len(resultsJson["RESULTS_EXPLOIT"]) == 0: #no results found						
								results = DeviceIsSecure
								results2= "[Prt:{}|Srv:{}] No exploites found by using the command:{}".format(port, Product,commands)
							else:
								results = DeviceNotSecure
								results2=  "[Prt:{}|Srv:{}]: {} exploites found by using the command:{}".format(port, Product,str(len(resultsJson["RESULTS_EXPLOIT"])), commands)
								resultsDetials = resultsJson
								printExploitsResults(resultsJson, port)
					except():
						pass
				else: #the test found expl. 
					results = DeviceNotSecure
					results2=  "[Prt:{}|Srv:{}]: {} exploites found by using the command:{}".format(port, Product,str(len(resultsJson["RESULTS_EXPLOIT"])), commands) 
					resultsDetials = resultsJson
					printExploitsResults(resultsJson, port)
			else:
				results = TestFailed 
				
		except Exception as e:
			results = TestFailed
			results2 = "[Prt:{}|Srv:{}] Error - {}".format(port, Product, str(e) ) 

	else:
		results= TestNotApplicable
		results2 = "[Prt:{}] The device did not reveal the product running that port".format(port) 


	print("[Nmap port info test]: Checking exploits of port: [{}] with service [{}] and command [{}]. The result is: [{}]".format(port, Product, command,  results)) 

	return results, results2, resultsDetials

def printExploitsResults(resultsJson, port):
	print("[Nmap port info test]: Found [{}] possible exploits for port [{}]".format(len(resultsJson["RESULTS_EXPLOIT"] ), port))
	counter = 0
	for exp in  resultsJson["RESULTS_EXPLOIT"]:
		print(exp["Title"])
		counter = counter + 1
		if counter == 3:
			print("...etc")
			break
	
def exportOutput(resultsDir,DeviceMAC, fileName_summ, result_sum1, result_sum2, fileName_Details = None, result_details = None ):


	filePath= os.path.join(resultsDir,DeviceMAC,fileName_summ)
	with open (filePath , "w") as fout: 
		fout.write(result_sum1)
		fout.write("\n")
		fout.write(result_sum2)

	if result_details is not None:
		filePath= os.path.join(resultsDir,DeviceMAC,fileName_Details )
		with open ( filePath, "w") as fout:
			json.dump(result_details, fout)	


code = "Nmap Port Info Test"
print ("[Test Running]: " + code)


fileName= os.path.join(temporaryFiles, DeviceIP+"_Ports")


with open(fileName) as f:
	data = f.read()
data = json.loads(data)

print("[Nmap port info test]: Finished the dedicated port scanning by Nmap")
nm= data 
portsData={}



AllIndeces = []
tcpPortsName = {}

if 'tcp' in nm:
	AllIndeces =  nm['tcp'].keys()
	tcpPortsName ={}
	for port in nm['tcp']:
		servc =nm['tcp'][port]['name']
		if servc in tcpPortsName:
			tcpPortsName[servc].append(port)
		else:
			tcpPortsName[servc] =[]
			tcpPortsName[servc].append(port)


print("[Nmap port info test]: Port found open: " + " ".join(map(str,AllIndeces)) )


################### Checking FTP service ##############################
FTPvulnerResults_sum = TestFailed
FTPvulnerResults_sum2 = TestFailed
FTPvulnerResults_details= None
FTPversionResult_sum = TestFailed
FTPversionResult_sum2 = TestFailed

name = "ftp"
try:

	if name in tcpPortsName:
		for port in tcpPortsName[name]:
			print("The port: {} with name: {} has CPE: {}".format(port, nm['tcp'][port]['product'] , nm['tcp'][port]['cpe']) )
			#FTP vulnerabilities
			FTPversionResult_sum = TestFailed
			FTPversionResult_sum, FTPversionResult_sum2 = checkVersionInJson(DeviceIP, port, "FTP.json")
			FTPvulnerResults_sum, FTPvulnerResults_sum2, FTPvulnerResults_details = checkVulnerbilityVersion(DeviceIP, port, nm['tcp'][port])

	else:# if port doesnt exists, the test is not applicable.
		FTPvulnerResults_sum  =TestNotApplicable
		FTPvulnerResults_sum2 = "The device does not have port "+ name
		FTPversionResult_sum=TestNotApplicable
		FTPversionResult_sum2 = "The device does not have port "+ name
		print("[Nmap port info test]: No FTP found in this device")

	
except Exception as e:
	exc_type, exc_obj, exc_tb = sys.exc_info()
	FTPvulnerResults_sum =TestFailed
	FTPvulnerResults_sum2 = "Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))
	FTPversionResult_sum=TestFailed
	FTPversionResult_sum2="Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))
	print("[Nmap port info test]: In FTP - Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e)) )

exportOutput(resultsDir,DeviceMAC, "FTPVersionTest_Summary" , FTPversionResult_sum, FTPversionResult_sum2 )
exportOutput(resultsDir,DeviceMAC, "FTPVulnerableTest_Summary" , FTPvulnerResults_sum, FTPvulnerResults_sum2, "FTPVulnerableTest_Details", FTPvulnerResults_details )



################### Checking SSH service ##############################
SSHvulnerResults_sum = TestFailed
SSHvulnerResults_sum2 = TestFailed
SSHvulnerResults_details= None
SSHversionResult_sum = TestFailed
SSHversionResult_sum2 = TestFailed


name = "ssh"
try:

	if name in tcpPortsName:
		for port in tcpPortsName[name]:
			print("The port: {} with name: {} has CPE: {}".format(port, nm['tcp'][port]['product'] , nm['tcp'][port]['cpe']))
			#SSH vulnerabilities
			SSHversionResult_sum = TestFailed
			SSHversionResult_sum, SSHversionResult_sum2 = checkVersionInJson(DeviceIP, port, "SSH.json")
			SSHvulnerResults_sum, SSHvulnerResults_sum2, SSHvulnerResults_details = checkVulnerbilityVersion(DeviceIP, port, nm['tcp'][port])
			exportOutput(resultsDir,DeviceMAC, "SSHVersionTest_Summary"+str(port), SSHversionResult_sum, SSHversionResult_sum2 )
			exportOutput(resultsDir,DeviceMAC, "SSHVulnerableTest_Summary" +str(port) , SSHvulnerResults_sum, SSHvulnerResults_sum2, "SSHVulnerableTest_Details"+str(port), SSHvulnerResults_details )

	else:# if port does not exists, the test is not applicable.
		SSHvulnerResults_sum  =TestNotApplicable
		SSHvulnerResults_sum2 = "The device does not have port "+ name
		SSHversionResult_sum=TestNotApplicable
		SSHversionResult_sum2 = "The device does not have port "+ name
		print("[Nmap port info test]: No SSH found in this device")
		exportOutput(resultsDir,DeviceMAC, "SSHVersionTest_Summary", SSHversionResult_sum, SSHversionResult_sum2 )
		exportOutput(resultsDir,DeviceMAC, "SSHVulnerableTest_Summary", SSHvulnerResults_sum, SSHvulnerResults_sum2, "SSHVulnerableTest_Details", SSHvulnerResults_details )
		
	
except Exception as e:
	exc_type, exc_obj, exc_tb = sys.exc_info()
	SSHvulnerResults_sum =TestFailed
	SSHvulnerResults_sum2 = "Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))
	SSHversionResult_sum=TestFailed
	SSHversionResult_sum2="Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))		
	print("[Nmap port info test]: In SSH - Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e)) )
	exportOutput(resultsDir,DeviceMAC, "SSHVersionTest_Summary", SSHversionResult_sum, SSHversionResult_sum2 )
	exportOutput(resultsDir,DeviceMAC, "SSHVulnerableTest_Summary", SSHvulnerResults_sum, SSHvulnerResults_sum2, "SSHVulnerableTest_Details", SSHvulnerResults_details )
	

################### Checking HTTP service ##############################
HTTPvulnerResults_sum = TestFailed
HTTPvulnerResults_sum2 = TestFailed
HTTPvulnerResults_details= None
HTTPversionResult_sum = TestFailed
HTTPversionResult_sum2 = TestFailed

#if port  HTTP
name = "http"
try:

	if name in tcpPortsName:
		for port in tcpPortsName[name]:
			print("The port: {} with name: {} has CPE: {}".format(port, nm['tcp'][port]['product'],  nm['tcp'][port]['cpe']) )
			#HTTP vulnerabilities
			HTTPversionResult_sum = TestFailed 
			HTTPversionResult_sum, HTTPversionResult_sum2 = checkVersionInJson(DeviceIP, port, "HTTP.json")
			HTTPvulnerResults_sum, HTTPvulnerResults_sum2,  FTPvulnerResults_details  = checkVulnerbilityVersion(DeviceIP, port, nm['tcp'][port])
			exportOutput(resultsDir,DeviceMAC, "HTTPVersionTest_Summary"+str(port) ,HTTPversionResult_sum, HTTPversionResult_sum2  )
			exportOutput(resultsDir,DeviceMAC, "HTTPVulnerableTest_Summary" +str(port) , HTTPvulnerResults_sum, HTTPvulnerResults_sum2, "HTTPVulnerableTest_Details"+str(port) , HTTPvulnerResults_details )

	else:# if port does not exists, the test is not applicable.
		HTTPvulnerResults_sum  =TestNotApplicable
		HTTPvulnerResults_sum2 = "The device does not have port "+ name
		HTTPversionResult_sum=TestNotApplicable
		HTTPversionResult_sum2 = "The device does not have port "+ name
		print("[Nmap port info test]: No HTTP found in this device")
		exportOutput(resultsDir,DeviceMAC, "HTTPVersionTest_Summary" ,HTTPversionResult_sum, HTTPversionResult_sum2  )
		exportOutput(resultsDir,DeviceMAC, "HTTPVulnerableTest_Summary" , HTTPvulnerResults_sum, HTTPvulnerResults_sum2, "HTTPVulnerableTest_Details" , HTTPvulnerResults_details )

except Exception as e :
	exc_type, exc_obj, exc_tb = sys.exc_info()
	HTTPvulnerResults_sum =TestFailed
	HTTPvulnerResults_sum2 = "Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))
	HTTPversionResult_sum=TestFailed
	HTTPversionResult_sum2 = "Error [Line:{}] {}".format( exc_tb.tb_lineno, str(e))	
	print("[Nmap port info test]: In HTTP - Test Error: line:{} {}".format( exc_tb.tb_lineno, str(e)))
	exportOutput(resultsDir,DeviceMAC, "HTTPVersionTest_Summary", HTTPversionResult_sum, HTTPversionResult_sum2  )
	exportOutput(resultsDir,DeviceMAC, "HTTPVulnerableTest_Summary", HTTPvulnerResults_sum, HTTPvulnerResults_sum2, "HTTPVulnerableTest_Details" , HTTPvulnerResults_details )

