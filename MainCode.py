import os, sys, shutil 
import time
import json
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import *
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QInputDialog, QAction
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtCore import QProcess


#loading the GUI..
from aidingScripts.layout_ver6 import Ui_IoTTestbed

#loading the Tests and Variables..
from aidingScripts.generalVariables import *
from aidingScripts.testsData import WiFiTestList
from aidingScripts.testsData import WiFiTestList_optional

#loading functionalities..
from aidingScripts.FuncsToAddDevices  import FuncsToAddDevices
from aidingScripts.UpdateDatabase import UpdateDatabase
from aidingScripts.databaseFunctions import databaseFunctions
from aidingScripts.GraphsAndConnection import GraphsAndConnection
from aidingScripts.CVEandDeviceInfoTab import CVEandDeviceInfoTab
from aidingScripts.BLETest import BLEtestClass

from aidingScripts.TestingPageClass import TestingPageClass
import datetime
import netifaces

from pyqtgraph.Qt import QtGui, QtCore
import pyqtgraph as pg
import pickle

#=======================================================================
#	This python script is dedicated to control the GUI of the testbed applicaiton
#	The app has 2 stages:
#		1) BLUETOOTH
#		2) WIFI, where tests can be done in devices connected in the same LAN.
#		   This LAN can be created thoough
#			a) Physical Access point. i.e. connecting to a physical externel router
#			b) Virtual Access point i.e. creating a virtual AP where devices can connect to.  <FROZEN>
#
#	The GUI consist of multiple tabs 
#
#


class IoTTestbed(QMainWindow, Ui_IoTTestbed, UpdateDatabase,databaseFunctions, FuncsToAddDevices, BLEtestClass, GraphsAndConnection, CVEandDeviceInfoTab , TestingPageClass ):

	TabBLE= None
	TabWIFI=None
	TabTestWIFI= None
	
	
	def __init__(self):
		super().__init__()
		self.setupUi(self)
		self.initialize_GUI()
		self.TabZero= self.ioTportalTab_0    # 0
		self.TabOne= self.ioTportalTab_1     # 1
		self.TabTwo=self.ioTportalTab_2     # 2
		self.TabThree= self.ioTportalTab_3# 3
		self.TabTestWIFI= self.WiFiTab      # 4
		self.TabBLE= self.BluetoothTab       # 5
		####################### End: Buttons #################################
		#--------------Initialization Area--------
		self.initializeBLE()
		self.initializeWiFi()
		self.initDatabase()
		self.InitializeGraphsAndConnection(app)
		self.initializeInfoDev()		
		###################### Start: Pages/Widgets ##############################
		self.activeWidgt(0)
		###################### Start: clearning up old dictories ##############################
		try:shutil.rmtree(temporaryFiles) #remove the directory
		except:pass
		if(not os.path.exists(temporaryFiles)): #make sure that temporaryFiles direcotiy exist 
			os.makedirs(temporaryFiles)

		try:shutil.rmtree(packetsFiles) #remove the directory
		except:pass
		
		if(not os.path.exists(packetsFiles)): #make sure that packetsFiles direcotiy exist 
			os.makedirs(packetsFiles)
		if(not os.path.exists(reportDir)): #make sure that resultsDirBLE direcotiy exist 
			os.makedirs(reportDir)	
			
		try:shutil.rmtree(resultsDirWIFI) #remove the directory
		except:pass
		
		try:shutil.rmtree(resultsDirBLE) #remove the directory
		except:pass
			
		if(not os.path.exists(GResultsDir)): #make sure that GResultsDir direcotiy exist 
			os.makedirs(GResultsDir)
		if(not os.path.exists(resultsDirBLE)): #make sure that resultsDirBLE direcotiy exist 
			os.makedirs(resultsDirBLE)	
		
		if(not os.path.exists(packetsFiles)): #make sure that packetsFiles direcotiy exist 
			os.makedirs(packetsFiles)
		if(not os.path.exists(reportDir)): #make sure that reportDirBLE direcotiy exist 
			os.makedirs(reportDir)							
		print("continue")


		
	
	#As buttons triggers or call fire functions once they are clicked, 
	#this funciton to initialize all the buttons used in the GUI with the functions triggered by them.
	def initialize_GUI(self):
		####################### Start: Buttons ##############################
		#initialize Buttons
		self.WifiGoTesting_btn.setEnabled(False)

		#testingtab .. welcomeWedget
		self.BlE_Test_btn.clicked.connect(lambda:self.activeWidgt(5))
		self.WiFi_Test_btn.clicked.connect(lambda:self.activeWidgt(1))

		#testingtab .. Wifi_chooseDevices
		self.AP_phy_btn.clicked.connect(self.AP_phy_func)
		self.AP_vr_btn.clicked.connect(self.AP_vr_func)
		self.ExitProgram_btn.clicked.connect(lambda:self.closeGUI(app))
		self.BLE_back2setting_btn.clicked.connect(lambda:self.activeWidgt(0))
		self.back2TestMode_btn.clicked.connect(lambda:self.activeWidgt(0))
		self.back2ChseAP_btn.clicked.connect(lambda:self.activeWidgt(1))
		self.back2ChseDev_btn.clicked.connect(lambda:self.activeWidgt(2))
		self.BackToSetting_btn.clicked.connect(lambda:self.activeWidgt(3))
		self.frmNetwork_RB.toggled.connect(lambda:self.toggledRB(1))
		self.frmCSV_RB.toggled.connect(lambda:self.toggledRB(2))
		self.ConfirmDevsLsit_btn.clicked.connect(lambda:self.activeWidgt(3))
		self.ConfirmDevsLsit_btn.clicked.connect(self.confirmDevs)
		self.StartTestingDeev_btn.clicked.connect(lambda:self.activeWidgt(4))
		self.StartTestingDeev_btn.clicked.connect(self.updatesTheList)
		self.Openfrmfile_btn.clicked.connect(self.readFromFile)
		self.StrtSrchNet_btn.clicked.connect(self.SrchFromNet)
		####################################################################

		self.StopThisTest_btn.clicked.connect(self.stopTestingThisDev)
		self.StopAllTests_btn.clicked.connect(self.stopTestingAllDevs)
		self.StopCurrentTest_btn.clicked.connect(self.stopTestingCurrentTest)
		####################################################################
		self.devInfo={}

		####################### Tests tab ##################
		self.loadTestList()
		self.AllTest_chkbox.stateChanged.connect(self.selectAllTests)
		#########################Connection table ############################
		self.connectionIPs={}
		self.tableConIndex = 0
		######################################################################

		
				

	########################################################################
	#UI only
	#This function to swap between the different tabs in GUI
	def activeWidgt(self, index):
		
		self.scanLoadOnlineDevs(False) #dont start new processes, just kill the previous one
		tabList = [self.TabZero, self.TabOne,self.TabTwo , self.TabThree, self.TabTestWIFI , self.TabBLE ]
		for tab in tabList:
			try:self.GUI_TabsWidget.removeTab(self.GUI_TabsWidget.indexOf(tab))
			except:
				print("[In Function: activeWidgt] Page is already deleted")
				pass
		if (index == 0):
			self.ioTportalTab_0 =  tabList[0]
			self.GUI_TabsWidget.addTab( tabList[0], "Testing Configuration")
		elif(index == 1):
			self.ioTportalTab_1 =  tabList[1]
			self.GUI_TabsWidget.addTab( tabList[1] , "Testing Configuration")
		elif(index == 2):
			self.ioTportalTab_2 =  tabList[2]
			self.GUI_TabsWidget.addTab( tabList[2], "Testing Configuration")
			self.ConfirmDevsLsit_btn.setEnabled(False)
			self.scanLoadOnlineDevs()
		elif(index == 3):
			self.ioTportalTab_3 =  tabList[3]
			self.GUI_TabsWidget.addTab( tabList[3], "Testing Configuration")
		elif(index == 4):
			self.WiFiTab =  tabList[4]
			self.GUI_TabsWidget.addTab(tabList[4], "Testing Zone")
		elif(index == 5):
			self.BluetoothTab =  tabList[5]
			self.GUI_TabsWidget.addTab(self.BluetoothTab, "Bluetooth Tab")
		self.GUI_TabsWidget.setCurrentIndex(self.GUI_TabsWidget.indexOf(tabList[index]))
		print("[In Function: activeWidgt] Flipping to the tab with index: ", index)

########################################################################
	#UI only
	#toggle between options of (database Managment TAB)
	def toggledRB(self, index):
		BoolOne=False
		BoolTwo=False

		if(index == 1):# option, from Network
			BoolOne = True
		elif(index == 2):# option, from CSV
			BoolTwo = True
		print("[In Function: toggledRB] the index in checkbox is ", index)

		self.StrtSrchNet_btn.setEnabled(BoolOne)
		self.Openfrmfile_btn.setEnabled(BoolTwo)

#########The following 2 funtions#######################################
	#Type: UI
	#Choose between Physical access point or Virtual access point
	#Action  will call function to shit to the new tabs
	def AP_phy_func(self):
		print("[In Function: AP_phy_func] AP_phy_func")
		self.BooleanPhyAp = True
		self.activeWidgt(2)

	def AP_vr_func(self):
		print("[In Function: AP_vr_func] AP_vr_func")
		self.BooleanPhyAp = False
		self.activeWidgt(2)
########################################################################


########################################################################
#UI to list all the devices available in the database.
#the funciton just calls another function from another file (FunctionsToAddDevices)
	def scanLoadOnlineDevs(self, StartNewProcess = True):
		
		#kill old process ( if any was still running)
		try:self.ScanDevsProcess.kill()
		except(AttributeError):
			print("[In Function: scanLoadOnlineDevs]** first time to run ScanDevsProcess **")
		
		if StartNewProcess:
			self.ListDeviceOfDB_combo.clear()

			try:
				netifaces.ifaddresses('wlan0') #make sure the testing machine has wlan0! else make excption
				self.DevicesInLan={}
				self.ListDevIndeces = []
				self.ScanDevsProcess = QProcess()
				self.ScanDevsProcess.setProcessChannelMode(QProcess.MergedChannels)
				self.ScanDevsProcess.readyReadStandardOutput.connect(self.ProcStartSrchFrDev_Func)
				path = os.path.join(aidingScripts, "AddDevByScanningLan.py")
				self.ScanDevsProcess.start("python3", ["-u",path])
				self.devicesExist= False
				self.ListDeviceOfDB_combo.addItem("**Wait please, the software is scanning the LAN.**")
				_,self.listofDevsInDB,_, _ = self.importDevsFromDB()

			except(ValueError):
				print("No wlan0 found!")
				self.ListDeviceOfDB_combo.addItem("**No wlan0 found! Kindly check the network interfaces**")


	def ProcStartSrchFrDev_Func(self):
		count = 0
		try:
			path= os.path.join(temporaryFiles,'ScannedDevsInLan.json')
			with open(path, 'r') as fin:
				List=json.load(fin)
				print (List)
				for key in List:
					mac   = List[key][1]
					if mac =="":
						mac ="This PC"
					else: 
						if mac not in self.DevicesInLan: #It is new, add it
							
							if mac in self.listofDevsInDB:
								IP    = List[key][0]
								mac   = List[key][1] 
								name  = self.listofDevsInDB[mac]['Name']
								ModelNo=self.listofDevsInDB[mac]['ModelNo']
								vendor= "_ **SAVED IN DB**"
							
							else:
															
								IP    = List[key][0]
								mac   = List[key][1]
								name  = List[key][2]
								vendor= List[key][3]
								
							item="MAC: "+mac+" |IP: "+ IP+ " |Name: "+name + " |Vendor: "+vendor
							if not self.devicesExist:
								self.devicesExist=True
								self.ConfirmDevsLsit_btn.setEnabled(True)
								self.ListDeviceOfDB_combo.clear()
								
							self.ListDeviceOfDB_combo.addItem( item )
							self.DevicesInLan[mac] = {"mac": mac, "IP":IP, "Name": name, "Vendor":vendor}
							self.ListDevIndeces.append(mac)
							
		except(FileNotFoundError):
			print('[In Function: ProcStartSrchFrDev_Func] ScannedDevsInLan.json file dont exist')
			
		except(json.decoder.JSONDecodeError):
			print('[In Function: ProcStartSrchFrDev_Func] ScannedDevsInLan.json file content dont exist')
				
########################################################################


######### The following (2) functions ##################################	
#UI 
#The following functions load tests from tests file. 
#So far this functionality is available only for Wi-Fi testing 
#The first function just load the tests add them to list Widget(UI) to be viewed by the user
	def loadTestList(self):
		self.ListOfTests_Combo.clear()
		try:

			tempTestList = [WiFiTestList[test]['TestDesc']  for test in WiFiTestList]		
			self.ListOfTests_Combo.addItems(tempTestList)		
			if len(WiFiTestList): #number of tests more than zero. enable the check box of (choose all)
				self.AllTest_chkbox.setEnabled(True)
		except Exception as e:
			print("\n\n\ERROR:\n"+str(e))
			self.ListOfTests_Combo.addItem("*** No tests***")
			self.AllTest_chkbox.setEnabled(False)
			pass

#The second function will be triggered if the user chose to select all tests..
	def selectAllTests(self):
		if self.AllTest_chkbox.isChecked():
			NumberOfTests = self.ListOfTests_Combo.count()
			for i in range(0,NumberOfTests):
				item = self.ListOfTests_Combo.item(i)
				item.setSelected(True)
########################################################################


#######################################################################		
##closing the software 
#You should delete processAP , process Nmap, process[mac]<<loop over this one.. stop the timer
	def closeGUI(self, app):

		print("[In Function: closeGUI] Stop the timer")
		try:self.processNmap.kill()
		except:pass	
						
		try:
			for mac in self.process:
				self.process[mac].kill()
				print("[In Function: closeEvent] killing the ", mac)
		except: pass
						
		try:
			self.processPacketCollector.kill()
			print("[In Function: closeEvent] killing the packetcollector")
		except: pass				
			
		try:
			self.processAP.kill()
			print("[In Function: closeEvent] killing the AP")
		except: pass	

		try:
			self.processNmap.kill()
			print("[In Function: closeEvent] killing the Nmap")
		except: pass	
		
											
		try:
			self.timer.stop()
			print("[In Function: closeEvent] killing the timer")
		except: 
			print("[In Function: closeEvent] Timer was not working ")
			pass
			
		try:
			self.getIP.kill()
			print("[In Function: closeEvent] killing the get IP")
		except: 
			print("[In Function: closeEvent] get IP was not working ")
			pass			

		try:
			self.process_ExportReport.kill()
			print("[In Function: closeEvent] Killing export report process ")
		except: 
			print("[In Function: closeEvent] Export report process was not working ")
			pass

		self.close()

	def closeEvent(self, *args, **kwargs):
		super(QMainWindow, self).closeEvent(*args, **kwargs)
		print("[In Function: closeEvent] Stop the timer")
		try:self.processNmap.kill()
		except:pass	
						
		try:
			for mac in self.process:
				self.process[mac].kill()
				print("[In Function: closeEvent] killing the ", mac)
		except: pass
						
		try:
			self.processPacketCollector.kill()
			print("[In Function: closeEvent] killing the packetcollector")
		except: pass				
			
		try:
			self.processAP.kill()
			print("[In Function: closeEvent] killing the AP")
		except: pass	

		try:
			self.processNmap.kill()
			print("[In Function: closeEvent] killing the Nmap")
		except: pass	
		
											
		try:
			self.timer.stop()
			print("[In Function: closeEvent] killing the timer")
		except: 
			print("[In Function: closeEvent] Timer was not working ")
			pass
			
		try:
			self.getIP.kill()
			print("[In Function: closeEvent] killing the get IP")
		except: 
			print("[In Function: closeEvent] get IP was not working ")
			pass			

		try:
			self.process_ExportReport.kill()
			print("[In Function: closeEvent] Killing export report process ")
		except: 
			print("[In Function: closeEvent] Export report process was not working ")
			pass


						
		sys.exit(0)		


if __name__ == "__main__":
	
	app = QApplication(sys.argv)
	main = IoTTestbed()
	main.show()
	sys.exit(app.exec_())
