import pexpect
import re, os, sys
import time
import subprocess


try:
	dir_path = os.path.dirname(os.path.realpath(__file__))
	parent_dir_path = os.path.abspath(os.path.join(dir_path, os.pardir))
	sys.path.insert(0, parent_dir_path)

	from aidingScripts import generalVariables
	TestFailed = generalVariables.TestFailedToLaunch
	DeviceNotSecure= generalVariables.DeviceIsntSecure
	DeviceIsSecure= generalVariables.DeviceIsSecure
	TestNotApplicable = generalVariables.TestNotApplicable
	resultsDirBLE = generalVariables.resultsDirBLE
	temporaryFiles = generalVariables.temporaryFiles
	testsDir=generalVariables.testsDir	
except:
	TestFailed =  "Test failed"
	DeviceNotSecure = "Vulnerable"
	DeviceIsSecure ="Not Vulnerable"
	TestNotApplicable ="Not Applicable"
	resultsDirBLE = "results/BLE"

try:
	DEVICE=  sys.argv[1]
except:
	DEVICE= "FB:55:7F:9E:0C:CF" 


resutls=TestFailed
results2 =""


bashCommand = "btmgmt le on"
process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
time.sleep(0.5)

child = pexpect.spawn("gatttool -I -t random  -b "+DEVICE)
child.sendline("connect")
print("Sending connectd")

try:
	child.expect("Attempting to connect to "+DEVICE, timeout=5 )
	child.expect("Connection successful")
	print("Connection successful")
	child.sendline("characteristics")
	print("Sending Charactersitics command")
	#child.expect("handle")
	i = 0
	while True:
		try:
			child.expect("handle", timeout=5)
			x =  child.before
			x= x.decode("utf_8")
			print ("handle"+ str(x))
			
		except pexpect.exceptions.TIMEOUT:
			print ("done")			
			child.sendline("disconnect")
			child.sendline("exit")

			results = DeviceNotSecure
			results2 = "Device characteristics were collected successfully."
			break		
except Exception as e:#pexpect.exceptions.TIMEOUT: #the device is not connected or not responding 
	print("No connection.", e)
	print("The device is not connected or is not responding")
	results = TestFailed
	results2 ="The device is not connected or it is not responding"

filePath = os.path.join(resultsDirBLE,  DEVICE, "getChar_Summary") 
with open (filePath , "w") as fout: 
	fout.write(results) 
	fout.write("\n") 
	fout.write(results2) 
    
print("Closing the conneciton")
child.close()
print("Results is: ", results)
