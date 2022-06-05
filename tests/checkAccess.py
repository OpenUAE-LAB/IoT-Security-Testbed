##firstly the code will lanuch a test access .. then it will try to sniff it ..
import glob
import json
import time
import requests, urllib.request
import os, sys


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
	
	
def start_counters(ckCounter):
	global IPofDUI
	global ListofSenders
	if ckCounter >0:
		print("Process file no: "+ str(ckCounter)+" for __ "+IPofDUI)

def checkOldPackets(MAC):
	result = TestFailed
	
	packetsSaveDir= 'PacketsFromToIoT'
	packetBranch = os.path.join('Packets', MAC, packetsSaveDir)
	fileNames = glob.glob(packetBranch+ "/*")
	fileNames = sorted( fileNames,   key = lambda file: os.path.getctime(file))
	
	if not len(fileNames):
		print("Packets directory not found")
		results2 = "Packets directory not found"
		return result, results2
	print("Start read/processing Pcap files in  "+ str(packetBranch))
	for file  in fileNames: 
		with open(file , "r") as fileN:
			dataAll =json.load(fileN)		
			for data in  dataAll:
				if dataAll[data]['Prtcl'] == "http":
					#check if there is authencation or not 
					try:			
						print ("ACCESS DATA is "+ dataAll[data]['pcktData']["http.authorization_tree"]["http.authbasic"])
						result = DeviceNotSecure
						print("!!!  Possible Vulnerability !!!! Authentication information is sent in clear text.")
						results2 = "Access data found " + dataAll[data]['pcktData']["http.authorization_tree"]["http.authbasic"]
						#return result, results2
					except KeyError:
						#print ("NO AUTH")
						pass
	result = DeviceIsSecure
	results2 = "No auth. info packets were found."
	return result, results2


def printoutResults(testResult, testResult2):
	print("Tests results are : ")
	print(testResult)			
	print(testResult2)	
	try:
		filePath= os.path.join(resultsDir,DeviceMAC,"checkAccess_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(testResult)		
			fout.write("\n")
			fout.write(testResult2)	

	except():
		pass




IP= sys.argv[1]
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]

url = 'http://'+IP
testResult = TestNotApplicable
testResult2 =""

#getting ports info
fileName= os.path.join(temporaryFiles, IP+"_Ports")
with open(fileName) as f:
	data = f.read()
data = json.loads(data)
nm= data 
portsData={}
AllIndeces = []
tcpPortsName = {}
#formating a dict to have dev info. 
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


#if port  HTTP
name = "http"
if name in tcpPortsName:

	try: #try to get HTML page
		handle = urllib.request.urlopen(url)
		print ("THere is a webpage")
		
		testResult = TestNotApplicable
		testResult2 = "The device has a webpage" 
		printoutResults(testResult, testResult2)


	except urllib.error.HTTPError as e:

		if e.code == 101 : #network issue!
			print("There is a network issue")
			testResult = TestFailed
			testResult2="There is a network issue" 
			printoutResults(testResult, testResult2)

		elif e.code  == 113 : #the device is not connected to LAN anymore!
			testResult = TestFailed
			testResult2= "The device is not connected to LAN anymore"				
			printoutResults(testResult, testResult2)

		elif e.code == 111 : #Connection refused
			testResult = TestNotApplicable
			testResult2= "The device doesnt have a webserver"	
			printoutResults(testResult, testResult2)

		elif e.code == 401: #authenticaiton is requrired 
			print("Authenticaiton is requrired ")
			try:
				r=requests.get(url, auth=("USER","PASSWD"))
				print("A request has been sent, the status code is: ", r.status_code)
				time.sleep(6)
				testResult, testResult2 = checkOldPackets(DeviceMAC)
				printoutResults(testResult, testResult2)
			except IOError as e:
				testResult = TestFailed
				testResult2=  "Error: " + str(e)
				printoutResults(testResult, testResult2)
		else:
			testResult = TestFailed
			testResult2=f"Error encountered: [{e.code}] {e.msg}"
			printoutResults(testResult, testResult2)	

	except urllib.error.URLError as e:

		if "library" in e.reason.__dict__:
			if  e.reason.library  == 'SSL':
				testResult = DeviceIsSecure
				testResult2="The device is using SSL"
				printoutResults(testResult, testResult2)	
		else:
			testResult = TestFailed
			testResult2=str(e.reason)
			printoutResults(testResult, testResult2)			


else:
	testResult = TestNotApplicable
	testResult2 = "The device does not have HTTP port."
	printoutResults(testResult, testResult2)	




