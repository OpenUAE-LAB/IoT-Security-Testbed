import subprocess,os,sys
from datetime import datetime 
import json


"""
This test checks multiple vulnerabilities:

1) Outdated Certifcate
2) Downgrade attack
3) Weak ciphers (SSL 1 or 2)
4) Short ciphers ()


"""


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
DeviceName=  sys.argv[2]
DeviceMAC=  sys.argv[3]
SSL = "sslscan " + IP 

code = "Checking the SSL Certificate"
print ("[Test Running]: " + code)

#Vulnerabilities to check..
#2) SSL/TLS renegotiation
renegotiation_Sum1 = TestNotApplicable 
renegotiation_Sum2 = ""
#3) Downgrade attack
Downgrade_Sum1 = TestNotApplicable
Downgrade_Sum2 = ""
#4) Outdated Certificate
OutDateCert_Sum1 = TestNotApplicable
OutDateCert_Sum2 = ""
#5) Ciphers length
CiphLength_Sum1 = TestNotApplicable
CiphLength_Sum2 = ""
#6) Ciphers  type
CipherType_Sum1 = TestNotApplicable
CipherType_Sum2 =  ""


"""
In case no webserver or HTTPs port was detected the sslScan tool prints the following 

Version: 1.11.13-static
OpenSSL 1.0.2-chacha (1.0.2g-dev)
"""

filePath =  os.path.join(temporaryFiles, IP+"_portsSummary")
with open(filePath) as fread:
	ports = fread.read()
	ports = json.loads(ports)
	
	# case 1: has port 80 and port 443
	if "443" in ports:
		

		#resSSL= 'Version: \x1b[32m1.11.13-static\x1b[0m\nOpenSSL 1.0.2-chacha (1.0.2g-dev)\n\x1b[0m\n\x1b[32mConnected to 192.168.10.1\x1b[0m\n\nTesting SSL server \x1b[32m192.168.10.1\x1b[0m on port \x1b[32m443\x1b[0m using SNI name \x1b[32m192.168.10.1\x1b[0m\n\n  \x1b[1;34mTLS Fallback SCSV:\x1b[0m\nServer \x1b[32msupports\x1b[0m TLS Fallback SCSV\n\n  \x1b[1;34mTLS renegotiation:\x1b[0m\nSession renegotiation \x1b[32mnot supported\x1b[0m\n\n  \x1b[1;34mTLS Compression:\x1b[0m\nCompression \x1b[32mdisabled\x1b[0m\n\n  \x1b[1;34mHeartbleed:\x1b[0m\nTLS 1.2 \x1b[32mnot vulnerable\x1b[0m to heartbleed\nTLS 1.1 \x1b[32mnot vulnerable\x1b[0m to heartbleed\nTLS 1.0 \x1b[32mnot vulnerable\x1b[0m to heartbleed\n\n  \x1b[1;34mSupported Server Cipher(s):\x1b[0m\n\x1b[32mPreferred\x1b[0m TLSv1.2  \x1b[32m256\x1b[0m bits  \x1b[32mECDHE-RSA-AES256-GCM-SHA384  \x1b[0m Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  ECDHE-RSA-AES256-SHA384       Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  DHE-RSA-AES256-SHA256         DHE 2048 bits\nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  DHE-RSA-AES256-SHA            DHE 2048 bits\nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  AES256-SHA256                \nAccepted  TLSv1.2  \x1b[32m256\x1b[0m bits  AES256-SHA                   \nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  \x1b[32mECDHE-RSA-AES128-GCM-SHA256  \x1b[0m Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  ECDHE-RSA-AES128-SHA256       Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  \x1b[32mDHE-RSA-AES128-GCM-SHA256    \x1b[0m DHE 2048 bits\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  DHE-RSA-AES128-SHA256         DHE 2048 bits\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  DHE-RSA-AES128-SHA            DHE 2048 bits\nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  AES128-SHA256                \nAccepted  TLSv1.2  \x1b[32m128\x1b[0m bits  AES128-SHA                   \n\x1b[32mPreferred\x1b[0m TLSv1.1  \x1b[32m256\x1b[0m bits  ECDHE-RSA-AES256-SHA          Curve P-256 DHE 256\nAccepted  TLSv1.1  \x1b[32m256\x1b[0m bits  DHE-RSA-AES256-SHA            DHE 2048 bits\nAccepted  TLSv1.1  \x1b[32m256\x1b[0m bits  AES256-SHA                   \nAccepted  TLSv1.1  \x1b[32m128\x1b[0m bits  ECDHE-RSA-AES128-SHA          Curve P-256 DHE 256\nAccepted  TLSv1.1  \x1b[32m128\x1b[0m bits  DHE-RSA-AES128-SHA            DHE 2048 bits\nAccepted  TLSv1.1  \x1b[32m128\x1b[0m bits  AES128-SHA                   \n\n  \x1b[1;34mSSL Certificate:\x1b[0m\nSignature Algorithm: \x1b[32msha256WithRSAEncryption\x1b[0m\nRSA Key Strength:    2048\n\nSubject:  FG101ETK18004610\nIssuer:   support\n\nNot valid before: \x1b[32mJul 30 01:48:33 2018 GMT\x1b[0m\nNot valid after:  \x1b[32mJan 19 03:14:07 2038 GMT\x1b[0m\n'
		#resSSL = 'Version: \x1b[32m1.11.13-static\x1b[0m\nOpenSSL 1.0.2-chacha (1.0.2g-dev)\n\x1b[0m\n\x1b[32mConnected to 192.168.10.8\x1b[0m\n\nTesting SSL server \x1b[32m192.168.10.8\x1b[0m on port \x1b[32m443\x1b[0m using SNI name \x1b[32m192.168.10.8\x1b[0m\n\n  \x1b[1;34mTLS Fallback SCSV:\x1b[0m\nServer \x1b[31mdoes not\x1b[0m support TLS Fallback SCSV\n\n  \x1b[1;34mTLS renegotiation:\x1b[0m\nSession renegotiation \x1b[32mnot supported\x1b[0m\n\n  \x1b[1;34mTLS Compression:\x1b[0m\nCompression \x1b[32mdisabled\x1b[0m\n\n  \x1b[1;34mHeartbleed:\x1b[0m\nTLS 1.2 \x1b[32mnot vulnerable\x1b[0m to heartbleed\nTLS 1.1 \x1b[32mnot vulnerable\x1b[0m to heartbleed\nTLS 1.0 \x1b[32mnot vulnerable\x1b[0m to heartbleed\n\n  \x1b[1;34mSupported Server Cipher(s):\x1b[0m\n\x1b[32mPreferred\x1b[0m TLSv1.2  \x1b[32m128\x1b[0m bits  \x1b[32mECDHE-ECDSA-AES128-GCM-SHA256\x1b[0m Curve P-256 DHE 256\n\n  \x1b[1;34mSSL Certificate:\x1b[0m\nSignature Algorithm: ecdsa-with-SHA256\nSubject:  001788fffea031e6\nIssuer:   \x1b[31m001788fffea031e6\x1b[0m\n\nNot valid before: \x1b[32mJan  1 00:00:00 2017 GMT\x1b[0m\nNot valid after:  \x1b[32mJan  1 00:00:00 2000 GMT\x1b[0m\n'
		#resSSL = 'Version: \x1b[32m1.11.13-static\x1b[0m\nOpenSSL 1.0.2-chacha (1.0.2g-dev)\n\x1b[0m\n'
		resSSL=subprocess.check_output(SSL,shell=True)
		resSSL=resSSL.decode("utf_8")
		resSSL = resSSL.replace("\x1b", "").replace("[32m", "").replace("[0m", "").replace("[1;34m", "").replace("[31m", "").replace("[33m", "").split("\n")
		for line in resSSL: 
			print( line)
			
		if len(resSSL) < 4 : 
			if "Version: 1.11.13-static" is resSSL[0]:
			#no webserver or HTTPs was found.
				CipherType_Sum1=TestFailed
				CipherType_Sum2 = "No Webserver found on ports 80/443"

		for line in resSSL:
			if len(line)> 16:
				if "Not valid after:" in line[:16]:
					try:
						serverDate = datetime.strptime(line[16:], '  %b %d %X %Y %Z')
						CurrentDate = datetime.now()
						
						print( CurrentDate)
						print( serverDate)
						if CurrentDate < serverDate:
							OutDateCert_Sum1 = DeviceIsSecure
							OutDateCert_Sum2 = "The certificate is updated"	
						else:
							OutDateCert_Sum1 = DeviceNotSecure
							OutDateCert_Sum2 = "The certificate is outdated it finished since: "+ str(line[16:])

					except Exception as e:
						print(e)
						
		try:
			index=resSSL.index("  TLS Fallback SCSV:")
			i = index+1 # to skip the "   TLS Fallback SCSV:" line
			if "Server does not support" in resSSL[i]: #vulnerable
				Downgrade_Sum1=DeviceNotSecure
				Downgrade_Sum2 = "Server does not support TLS Fallback SCSV"
			else:
				Downgrade_Sum1=DeviceIsSecure
				Downgrade_Sum2 = "Server does support TLS Fallback SCSV"
		except:pass		

		try:
			index=resSSL.index("  TLS renegotiation:")
			i = index+1 # to skip the "  TLS renegotiation:" line
			if "Session renegotiation not supported" in resSSL[i]: # Not vulnerable
				renegotiation_Sum1= DeviceIsSecure
				renegotiation_Sum2 = "Server secure against session renegotiation"
			else:
				renegotiation_Sum1=DeviceNotSecure
				renegotiation_Sum2 = "Server vulnerable against session renegotiation"
		except:pass	


		try:
			index=resSSL.index('  Supported Server Cipher(s):')
			i = index+1 # to skip the "Supported Server Cipher(s):" line
			while len(resSSL[i]):
				if "SSLv1" in resSSL[i] or  "SSLv2" in resSSL[i]: #vulnerable
					CipherType_Sum1 =DeviceNotSecure
					CipherType_Sum2 = "Server uses weak SSL [ "+ resSSL[i]+" ]."
				else:
					CipherType_Sum1 =DeviceIsSecure
					CipherType_Sum2 = "Server doesnt use weak SSLv1 and SSLv2"				
				i = i +1
		except:pass	


		"""
		resSSL after  splitting by empty space
		['Accepted', '', 'TLSv1.2', '', '128', 'bits', '', 'AES128-SHA', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '', '']
		['Preferred', 'TLSv1.1', '', '256', 'bits', '', 'ECDHE-RSA-AES256-SHA', '', '', '', '', '', '', '', '', '', 'Curve', 'P-256', 'DHE', '256']
		"""

		try:
			index=resSSL.index('  Supported Server Cipher(s):')
			i = index + 1 # to skip the "Supported Server Cipher(s):" line
			while len(resSSL[i]):
				temp = resSSL[i].split(" ")
				
				checkIndex = 4
				if "Preferred" == temp[0]:
					checkIndex = 3
					
				if int(temp[checkIndex]) < 128:
					CiphLength_Sum1=DeviceNotSecure
					CiphLength_Sum2 = "The certifcate uses short cipher key length (less than 128 bits)"
					break
				else: 
					CiphLength_Sum1=DeviceIsSecure
					CiphLength_Sum2 = "The certifcate uses long cipher key length (>=128 bits)"				

				i = i +1
		except:pass	
				

		print("Tests results: ")
		print (renegotiation_Sum1 ,"  " , renegotiation_Sum2)
		print (Downgrade_Sum1     ,"  " , Downgrade_Sum2)
		print (CiphLength_Sum1    ,"  " , CiphLength_Sum2)
		print (CipherType_Sum1    ,"  " , CipherType_Sum2)
		print (OutDateCert_Sum1   ,"  " , OutDateCert_Sum2)

		filePath= os.path.join(resultsDir,DeviceMAC,"renegotiation_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(renegotiation_Sum1)				
			fout.write("\n")
			fout.write(renegotiation_Sum2)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"Downgrade_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(Downgrade_Sum1)				
			fout.write("\n")
			fout.write(Downgrade_Sum2)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"CiphLength_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(CiphLength_Sum1)				
			fout.write("\n")
			fout.write(CiphLength_Sum2)	
					
		filePath= os.path.join(resultsDir,DeviceMAC,"CipherType_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(CipherType_Sum1)				
			fout.write("\n")
			fout.write(CipherType_Sum2)		
				
		filePath= os.path.join(resultsDir,DeviceMAC,"OutDateCert_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(OutDateCert_Sum1)				
			fout.write("\n")
			fout.write(OutDateCert_Sum2)				
							
	# case 2: has port 80 only wihtout a certificate
	elif "80" in ports:
		CipherType_Sum1=DeviceNotSecure
		CipherType_Sum2 = "No certificate in this device"
		print (CipherType_Sum1)
		print (CipherType_Sum2)
			
		filePath= os.path.join(resultsDir,DeviceMAC,"CipherType_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(CipherType_Sum1)				
			fout.write("\n")
			fout.write(CipherType_Sum2)		
					
	# case 3: no webserver
	else:
		CipherType_Sum1=TestNotApplicable
		CipherType_Sum2 = "The device doesnt have webserver on ports 80/443"
		print (CipherType_Sum1)
		print (CipherType_Sum2)

		filePath= os.path.join(resultsDir,DeviceMAC,"CipherType_Summary" )
		with open (filePath , "w") as fout: 
			fout.write(CipherType_Sum1)				
			fout.write("\n")
			fout.write(CipherType_Sum2)		


