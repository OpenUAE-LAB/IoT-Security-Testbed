#checked 14/1/2018

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
results = ""


code = "Search for BruteForce Directories"
print ("[Test Running]: ", code)

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
		
	command = "dirb http://" + IP + " -S" #silence mode
	print ("[Test Running]: " + command)
	results=False
	SummaryResult=TestFailed
	SummaryResult2 = ""
	try:
		results=subprocess.check_output(command,shell=True,stderr=open(os.devnull, 'w'))
		NumOfOpenPages = 0
		results=results.decode("utf_8")
		resultsLines=results.split("\n")
			
		for line in range(len(resultsLines)-1, 0, -1):
			if resultsLines[line] != "": #if line is not empty
				NumOfOpenPages = int(resultsLines[line].split("-")[1].split(":")[1])
				print(str(NumOfOpenPages) +  " web pages found opend")
				break

		print("Directories found are: ")
		for line in resultsLines:
			if ("+ http://" in line ):
				print(line)

		
		SummaryResult=DeviceIsSecure
		if (NumOfOpenPages > 5):
			SummaryResult=DeviceNotSecure
		SummaryResult2=str(NumOfOpenPages)+ " web pages found opend"
	except Exception as e:
		error = e
		try:
			if (error.returncode == 225):
				#device doesnt have http port!
				SummaryResult=TestNotApplicable
				SummaryResult2 = "Device doesn't have http port!"
			else:
				SummaryResult = TestFailed
				SummaryResult2 = "Error occured:"+ str(e)			
		except Exception as e:		
			SummaryResult = TestFailed
			SummaryResult2 = "Error occured: Err:{} - Err:{}".format(str(error), str(e))

else:
	SummaryResult=TestNotApplicable
	SummaryResult2 = "Device doesn't have http port!"

print ("[Test Running]: The result is [{}]: {}".format(SummaryResult, SummaryResult2) )

if len(results):
	filePath= os.path.join(resultsDir,DeviceMAC,"DirList_Detailed" )
	with open (filePath , "w") as fout: 
		fout.write(results)	

filePath = os.path.join(resultsDir, DeviceMAC, "DirList_Summary" )
with open (filePath , "w") as fout: 
	fout.write(SummaryResult) 
	fout.write("\n")
	fout.write(SummaryResult2)		
