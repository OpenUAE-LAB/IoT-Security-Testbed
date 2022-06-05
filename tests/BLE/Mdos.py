import sys,os, subprocess

#os.system('sudo l2ping FB:55:7F:9E:0C:CF')
#os.system('sudo l2ping FB:55:7F:9E:0C:CF')
"""

if os.system('echo $?') == 0:
	os.system('PASS > Mdos-result')
else:
	os.system('Fail > Mdos-result')

"""
try:
	from aidingScripts import generalVariables
	
	TestFailed = generalVariables.TestFailedToLaunch
	DeviceNotSecure= generalVariables.DeviceIsntSecure
	DeviceIsSecure= generalVariables.DeviceIsSecure
	TestNotApplicable = generalVariables.TestNotApplicable
	resultsDirBLE = generalVariables.resultsDirBLE 
except:
	TestFailed =  "Test failed"
	DeviceNotSecure = "Maybe Vulnerable"
	DeviceIsSecure ="Not Vulnerable"
	TestNotApplicable ="Not Applicable"
	resultsDirBLE = "results/BLE"

code = "DoS attack (ping of death)"
print ("[Test Running]: " + code)



DeviceMAC=  sys.argv[1]
result = TestFailed
command = "sudo l2ping "+ DeviceMAC+" & sleep 5 && pkill --signal SIGINT l2ping"

try:
	results=subprocess.check_output(command,shell=True,stderr=open(os.devnull, 'w'))
	results = results.decode("utf_8")
	resultsLines=results.split("\n")
	print(len(resultsLines) )
	if len(resultsLines) > 3: #i.e. the attack still going for longer time
		 result = DeviceNotSecure
		 
	else: #the attack was blocked..
		result = DeviceIsSecure
		
except(): 
	result = TestFailed
	print("Error")
	
print ("[Test Running]: " + result)
filePath = os.path.join(resultsDirBLE,  DeviceMAC, "Mdos_Summary")
with open (filePath , "w") as fout: 
	fout.write(result) 
