import gammu
import time

sm = gammu.StateMachine()
sm.ReadConfig()
sm.Init()

def getLastMessage(nb_attempt): #Based on GetSMS which is more accurate, but more slow
    attempt = nb_attempt
    lastloc = 1
    while attempt > 0:
        try:
            sms = sm.GetSMS(Folder=3, Location= lastloc)
            print "Location:%s\t State:%s\t Folder:%s\t Text:%s" % (lastloc,sms[0]['State'],sms[0]['Folder'],sms[0]['Text'])
        except gammu.ERR_TIMEOUT:
            return lastloc - 1
        except gammu.ERR_UNKNOWNRESPONSE:
            attempt = attempt - 1
        lastloc = lastloc + 1
    return None

def getLastMessage2(): #Based on GetNextSMS
    start = True
    lastloc = 0
    while 1:
        try :
            if start:
                sms = sm.GetNextSMS(Start = True, Folder=0)
                start = False
            else:
                sms = sm.GetNextSMS(Location = sms[0]['Location'], Folder=0)#be careful sometimes Location is directly in the hash so you'll have to remove the [0]
        except gammu.ERR_EMPTY:
            lastloc = sms[0]['Location']
            break
    while lastloc != 0:
        try:
            sm.GetSMS(Folder=0, Location=lastloc)
            return lastloc
        except gammu.ERR_TIMEOUT:
            lastloc = lastloc - 1

def processSMS(sms):
    print sms#Do whatever you want with the SMS :)
    pass
    
def example_loop(loc,variant):
    nb = 0
    first = True
    while 1:
        try:
            infos = sm.GetSMSStatus()
            tmp = dict()
            if variant == "UnRead":
                tmp = infos['SIMUnRead'] + infos['PhoneUnRead']
            elif variant == "Used":
                tmp = infos['SIMUsed'] + infos['PhoneUsed']
            if first:
                nb = tmp
                first = False
            else:
                if tmp != nb:
                    pos = loc+(tmp-nb)
                    sms = sm.GetSMS(Folder=3,Location=pos)
                    processSMS(sms)
                    loc = loc + (tmp-nb)
                    nb = tmp
            #print "Nb:%s\t loc:%s\t Infos:%s" % (nb,loc,infos)
            time.sleep(2)
        except gammu.GSMError:
            pass

if __name__ == "__main__":
    res = getLastMessage2()
    example_loop(res,"Used")