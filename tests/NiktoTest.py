import subprocess,os,sys


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
	temporaryFiles = "temporaryFiles"


IP= sys.argv[1]
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]


command="nikto -host " + IP
print("Command used: ", command)
testResult= TestNotApplicable
testResult2 = ""


#create variables:
XContentString="-"
XContentResult= TestNotApplicable

AllowString="HTTP headers allowed are not suspicious"
AllowResult = DeviceIsSecure

CrossDomString="This service wasn't found in the device"
CrossDomResult = TestNotApplicable


DefaultPassString="No default pass was found, maybe the device doesn't use/need authentication"
DefaultPassResult = TestNotApplicable

UPnPString="No UPnP XML file were found"
UPnPResult = TestNotApplicable
try:	
	results=subprocess.check_output(command,shell=True,stderr=open(os.devnull, 'w'))
	results=results.decode("utf_8")
	resultsLines = results.split("\n")

	
	if len(resultsLines)< 5:
		print("The host was not found")
		testResult2 = "The host was not found"
		testResult= TestFailed
		
		filePath= os.path.join(resultsDir,DeviceMAC,"AllowHeaders_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(testResult)		
			fout.write("\n")
			fout.write(testResult2)
			
	elif "No web server found" in resultsLines[2]:
		testResult2 = "The host doesn't have webserver on port 80"
		testResult= TestNotApplicable		
		print("results of the command")
		print (testResult2)
		filePath= os.path.join(resultsDir,DeviceMAC,"AllowHeaders_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(testResult)		
			fout.write("\n")
			fout.write(testResult2)

								
	else:
		print (resultsLines	)	
		for line in resultsLines:
		
			if "X-Content-Type-Options header is not set" in line :
				XContentString ="X-Content-Type-Options header is not set"
				XContentResult= DeviceNotSecure
				
				
			elif "Allowed HTTP Methods:" in line :
				if "TRACEBALE" in line or "PUT" in line or "DELETE" in line : 
					AllowString = line[2:]
					AllowResult = DeviceNotSecure
					
					
			elif "/crossdomain.xml " in line  :
				CrossDomString = "/crossdomain.xml was found, this could lead to problems"
				CrossDomResult = DeviceNotSecure

			elif "Default account found for" in line:
				DefaultPassString = line[2:]
				DefaultPassResult = DeviceNotSecure
				
				
			elif "Device UPnP XML file found" in line :
				UPnPString = line[2:]
				UPnPResult = DeviceNotSecure
						

		filePath= os.path.join(resultsDir,DeviceMAC,"AllowHeaders_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(AllowResult)		
			fout.write("\n")
			fout.write(AllowString)

		filePath= os.path.join(resultsDir,DeviceMAC,"XContent_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(XContentResult)		
			fout.write("\n")
			fout.write(XContentString)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"CrossDom_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(CrossDomResult)		
			fout.write("\n")
			fout.write(CrossDomString)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"DefaultPass_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(DefaultPassResult )		
			fout.write("\n")
			fout.write(DefaultPassString)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"UpnpXml_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(UPnPResult)		
			fout.write("\n")
			fout.write(UPnPString)
		
except Exception as e:
	exc_type, exc_obj, exc_tb = sys.exc_info()
	print("[Nikto test] Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e)))
	testResult=TestFailed
	
	filePath= os.path.join(resultsDir,DeviceMAC,"Nikto_Summary" )
	with open (filePath , "w") as fout: 
		fout.write(testResult)		
		fout.write("\n")
		fout.write("Error "+ str(e))
