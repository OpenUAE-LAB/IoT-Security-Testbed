import os, sys
import nmap
import time, netifaces
import generalVariables
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
	TestFailed =  "Test Failed"
	DeviceNotSecure = "Vulnerable"
	DeviceIsSecure ="Not Vulnerable"
	TestNotApplicable ="Not Applicable"
	resultsDir ="results/WiFi"
	temporaryFiles = "temporaryFiles"
	testsDir="tests"
	


	
IP= sys.argv[1]
IPofDUI = IP
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]
		
		
print("Run NMAP port scanning on: ", IPofDUI)

nm=nmap.PortScanner()
nm.scan(hosts=IPofDUI, arguments = " --max-retries 3 -Pn -sU  -p 5000")


if "udp" in nm[IPofDUI]:
	UDPPorts = {}
	print("Checking the UDP ports")
	for port in nm[IPofDUI]["udp"]:
		print("Port number: {} Name: {} State: {}".format( port, nm[IPofDUI]["udp"][port]['name'] ,   nm[IPofDUI]["udp"][port]['state']))
		UDPPorts[port]= {"Name": nm[IPofDUI]["udp"][port]['name'], "State":  nm[IPofDUI]["udp"][port]['state']}
		
	Ports_sum = "Done"
	Ports_sum2 = str(len(nm[IPofDUI]["udp"]))+" UDP port(s) found open"
	filePath= os.path.join(resultsDir,DeviceMAC,"ExtensiveNmap_summary" )
	with open ( filePath, "w") as fout: 
		fout.write(Ports_sum)
		fout.write("\n")
		fout.write(Ports_sum2)
	
	filePath= os.path.join(resultsDir,DeviceMAC,"ExtensiveNmap_details" )
	with open ( filePath, "w") as fout: 
		josn.dump(UDPPorts, fout)
		
