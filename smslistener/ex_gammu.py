#Import gammu module
import gammu

#initiate connection to the phone using default file configuration "~/.gammurc
sm = gammu.StateMachine()
sm.ReadConfig()
sm.Init()

#Send SMS
message = {
    'Text': 'python-gammu testing message', 
    'SMSC': {'Location': 1},
    'Number': '+420800123465',
}
sm.SendSMS(message)


#give a call
sm.DialVoice(phone_number)


#Main Exception from which all others Exception heritate.
except gammu.GSMError, val:

except (gammu.ERR_NOTSUPPORTED, gammu.ERR_NOTIMPLEMENTED):

#Get Netowrk informations
sm.GetNetworkInfo()

#Get infos
sm.GetManufacturer()
sm.GetModel()
sm.GetFirmware()
sm.GetIMEI()
sm.GetOriginalIMEI()
sm.GetProductCode()
sm.GetSIMIMSI()
sm.GetSMSC()
sm.GetHardware()
sm.GetManufacturerMonth()
sm.GetPPM() #language packs in the phone

#et SMS  infos
sm.GetSMSStatus() #Return number of SMS read/unread etc..
sm.GetSMSFolders() # Return folders as hash with attributes 

#Read SMS
sms = sm.GetNextSMS(Start = True, Folder=0)
#and then
sms = sm.GetNextSMS(Location = sms['Location'], Folder=0)

#To get a specific sms
sms = sm.GetSMS(Location = loc, Folder = 0)

#Loop through them
def printSMS():
	start = True
	while 1:
		try :
			if start:
				sms = sm.GetNextSMS(Start = True, Folder=0)
				start = False
			else:
				sms = sm.GetNextSMS(Location = sms[0]['Location'], Folder=0)#be careful sometimes Location is directly in the hash so you'll have to remove the [0]
		except gammu.ERR_EMPTY:
			break
		print "Location:%s\t State:%s\t Folder:%s\t Text:%s" % (sms[0]['Location'],sms[0]['State'],sms[0]['Folder'],sms[0]['Text'])


#get contacts informations from PhoneBook
phoneBookStatus = sm.GetMemoryStatus(Type = 'ME') # ou SM

#Get information about phonebook
#availables types : 'ME', 'SM', 'ON', 'DC', 'RC', 'MC', 'MT', 'FD', 'VM'
contact = sm.GetNextMemory(Start=True,Type='ME') #mobile phone
contact = sm.GetNextMemory(Location = contact['Location'],Type='ME')
..

#Note: Be carefull to catch gammu.ERR_TIMEOUT instead of EMPTY


#TODO
sm.GetToDoStatus()
todo = sm.GetNextToDo(Start = True)
sm.GetNextToDo(Location = todo['Location'])

sm.GetTodo(location)

#Calendar
sm.GetCalendarStatus()
cal = sm.GetNextCalendar(Start = True)
sm.GetNextCalendar(cal['Location'])

sm.GetCalendar(Location = location)


#---Others methods---
EnterSecurityCode(Type,Code,NewPIN) #Type(String) PIN, PUK, PIN2, PUK2, Phone. Code and NewPin string
GetAlarm() #Return alarm set in phone
GetBatteryCharge() #Retrn battery infos
GetFileSystemStatus() #Return file system status
GetFolderListing("folder",True) #Get next filename from filesystem
GetSecurityStatus()
GetSignalQuality() 
#------------

MAC_Prefixes = {
        'Sony-Ericsson' : ['00:01:EC','00:0A:D9','00:0E:07','00:0F:DE','00:12:EE','00:15:E0',
            '00:16:20','00:16:B8','00:18:13','00:19:63','00:1A:75','00:1B:59',
            '00:1C:A4','00:1D:28','00:1E:45','00:80:37',
            ],
        'Nokia' : ['00:02:EE','00:0B:E1','00:0E:ED','00:0F:BB','00:10:B3','00:11:9F',
            '00:12:62','00:13:70','00:13:FD','00:14:A7','00:15:2A','00:15:A0',
            '00:15:DE','00:16:4E','00:16:BC','00:17:4B','00:17:B0','00:18:0F',
            '00:18:42','00:18:8D','00:18:C5','00:19:2D','00:19:4F','00:19:79',
            '00:19:B7','00:1A:16','00:1A:89','00:1A:DC','00:1B:33','00:1B:AF',
            '00:1B:EE','00:1C:35','00:1C:9A','00:1C:D4','00:1C:D6','00:1D:3B',
            '00:1D:6E','00:1D:98','00:1D:E9','00:1D:FD','00:1E:3A','00:1E:3B',
            '00:1E:A3','00:1E:A4','00:40:43','00:A0:8E',
            '00:E0:03',
            ],
        'Siemens' : ['00:01:E3','00:05:19','00:0B:23','00:0B:A3','00:0D:41','00:0E:8C',
            '00:0F:BB','00:11:06','00:11:33','00:13:A3','00:18:D1','00:19:28','00:19:99',
            '00:1A:D0','00:1A:E8','00:1B:1B','00:1C:06','00:30:05','00:50:07',
            '00:90:40','00:C0:E4','08:00:06',
            ],
        'Samsung' : ['00:00:F0','00:02:78','00:09:18','00:0D:AE','00:0D:E5','00:0F:73',
            '00:12:47','00:12:FB','00:13:77','00:15:99','00:15:B9','00:16:32',
            '00:16:6B','00:16:6C','00:16:DB','00:17:C9','00:17:D5','00:18:AF',
            '00:1A:8A','00:1B:98','00:1C:43','00:1D:25','00:1D:F6','00:1E:7D',
            '00:E0:64',
            ],
        'LG' : ['00:05:C9','00:0B:29','00:12:56','00:14:80','00:19:A1','00:1C:62',
            '00:1E:75','00:1E:B2','00:50:CE','00:E0:91',
            ],
        'BenQ' : ['00:03:9D','00:17:CA',
            ],
        'Motorola' : ['00:01:AF','00:04:56','00:04:BD','00:08:0E','00:0A:28','00:0B:06',
            '00:0C:E5','00:0E:5C','00:0E:C7','00:0F:9F','00:11:1A','00:11:80',
            '00:11:AE','00:12:25','00:12:8A','00:12:C9','00:13:71','00:14:04',
            '00:14:9A','00:14:E8','00:15:2F','00:15:9A','00:15:A8','00:16:26',
            '00:16:75','00:16:B5','00:17:00','00:17:84','00:17:E2','00:17:EE',
            '00:18:A4','00:18:C0','00:19:2C','00:19:5E','00:19:A6','00:19:C0',
            '00:1A:1B','00:1A:66','00:1A:77','00:1A:AD','00:1A:DB','00:1A:DE',
            '00:1B:52','00:1B:DD','00:1C:11','00:1C:12','00:1C:C1','00:1C:FB',
            '00:1D:6B','00:1D:BE','00:1E:46','00:1E:5A','00:1E:8D','00:20:40',
            '00:20:75','00:A0:BF','00:C0:F9','00:E0:0C',
            ],
        'Alcatel' : ['00:07:72','00:08:9A','00:0E:86','00:0F:62','00:11:3F','00:11:8B',
            '00:15:3F','00:16:4D','00:17:CC','00:19:8F','00:1A:F0','00:1C:8E',
            '00:1D:4C','00:20:32','00:20:60','00:20:DA','00:80:21','00:80:39',
            '00:80:9F','00:A0:81','00:C0:BE','00:D0:95','00:D0:F6','00:E0:B1',
            '00:E0:DA',
            ],
        }
