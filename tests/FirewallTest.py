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


code = "Checking Firewall"
print ("[Test Running]: " + code)


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

		

	Fire = "wafw00f http://" + IP

	resultsummary=TestFailed
	resultsummary2=""
	try:
		Fire=subprocess.check_output(Fire,shell=True,stderr=open(os.devnull, 'w'))
		
		try:
			Fire=Fire.decode('utf_8')
			
		except AttributeError:
			print("Could not execute decode.(utf_8)")
			pass

		z=Fire.split('\n')	
		try:

			for row in z:
				if "No WAF detected" in row:
					print("[Checking Firewall Test]: No firewall found")
					resultsummary=DeviceNotSecure
					resultsummary2 = "No firewall found"

				elif "is behind" in row or "seems to be behind a WAF or some sort of security solution" in row:
					print("[Checking Firewall Test]: firewall found. " + row)	
					resultsummary=DeviceIsSecure
					resultsummary2 = row
				elif "reason" in row.lower():
					resultsummary2 = resultsummary2 + row

			if resultsummary2 == "":
				
				resultsummary2 = "No enough info to determine, kindly try out the command wafw00f http://"+IP

		except Exception as e:
			exc_type, exc_obj, exc_tb = sys.exc_info()	
			resultsummary=TestFailed
			resultsummary2="Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))	

	except subprocess.CalledProcessError:
		exc_type, exc_obj, exc_tb = sys.exc_info()	
		resultsummary=TestFailed
		resultsummary2="Error [Line:{}]: {}".format( exc_tb.tb_lineno, str(e))

else: 
	resultsummary = TestNotApplicable
	resultsummary2 = "The device does not have HTTP port."

print(f"Results: {resultsummary}: {resultsummary2}")

filePath= os.path.join(resultsDir,DeviceMAC,"FirewallTest_Summary" )
with open (filePath , "w") as fout: 
	fout.write(resultsummary)				
	fout.write("\n")
	fout.write(resultsummary2)
