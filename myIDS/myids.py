#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------#
	#Author: Robin David
	#Matriculation: 10014500
	#License: Creative Commons
#-----------------------------------#
import sys #for future parsing args
import os
import threading
import socket
from pcapy import findalldevs, open_live, open_offline
from impacket import ImpactDecoder, ImpactPacket
import datetime
import time
import string
# --- Include of written modules ---
from sniffer import AnalysePacket
from PortScan import PortScan
from nmap_os_scan import OSScan
from msn_protocol import MSN
from facebook import Facebook
from bbc import BBC
from botnet import botnet
#-----------------------------------

def get_interface():
    inter = findalldevs()
    i=0
    for eth in inter:
        print " %d - %s" %(i,inter[i])
        i+=1
    value=input(" Select interface: ")
    return inter[value]

#interface = get_interface() 

def getLocalIP():
    #if os.uname()[0].startswith("Li"):
	if not os.name == "nt":
		import fcntl, struct
		s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', interface[:15]))[20:24])
	else:
		return socket.gethostbyname(socket.gethostname())

#---- Instantiation of modules (even not used) ---#		
interface = get_interface()
portscan = PortScan(getLocalIP(),["classic"] , False,"medium")
osscan = OSScan("192.168.0.57","perfect")
sniffer = AnalysePacket()
msn = MSN(getLocalIP(),True)
fb = Facebook()
bbc = BBC()
botnet = botnet()
#-------------------------------------------------#

def event_packet_received(header, data):
	recieve_date = time.time()
	
	#-- Call the analyse function --#
	osscan.analyse(data,recieve_date)
	portscan.analyse(data)
	#sniffer.analyse(data)
	msn.analyse(data)
	fb.analyse(data)
	bbc.analyse(data)
	botnet.analyse(data,recieve_date)
	#-------------------------------#
	
def launch_capture(interface_to_listen):
    # Open a live capture
    p = open_live(interface_to_listen, 1500, 0, 100)    
    #p = open_offline("mycapture.pcap")
    print "Listening on %s: ip=%s net=%s, mask=%s\n" % (interface_to_listen, getLocalIP(), p.getnet(), p.getmask())
    
    #p.setfilter(get_filter())
        
    try:
		p.loop(0, event_packet_received) 
    except KeyboardInterrupt:
		print "Keybord interrupt recieved !"
		sys.exit(0)

''' not used yet
def get_filter():
    #Imagine you read a file and retrieve some filters
    i=0
    for f in filt:
        fil += " "+filt
        i+=1
    return fil
'''
    
def main():
    #Retreive normally arguments
    if interface:
        launch_capture(interface)
        

if __name__ == "__main__":
    main()