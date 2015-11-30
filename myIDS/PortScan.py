#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------#
	#Author: Robin David
	#Matriculation: 10014500
	#License: Creative Commons
#-----------------------------------#
import string
from impacket import ImpactDecoder, ImpactPacket #packet manipulation module
from datetime import datetime

from packet_function import *
import time

class SuspectHost:
    def __init__(self, ip):
		self.ip = ip
		self.portlist = list()
		self.lastpacketdate = time.time()
	
    def getName(self):
		return self.ip
	
    def getPorts(self):
		return self.portlist
	
    def addPort(self, port):
		exist = False
		for i in range(len(self.portlist)):
			if self.portlist[i][0] == port:
				exist = True
				self.portlist[i][1] += 1 #add 1 to the number of packets
		if not exist:
			self.portlist.append([port,1])
		self.lastpacketdate = time.time() #update the date of the reception of the last packet
    def calculateThreat_ratio(self):
		sum_rate = 0
		nb_packets = 0
		for i in range(len(self.portlist)):
			nb_packets += self.portlist[i][1]
			sum_rate += 100 / self.portlist[i][1]
		return sum_rate / len(self.portlist)
		
    def getLastPacketDate(self):
		return self.lastpacketdate

class PortScan:
	def __init__(self, ip, scantype, node=True, sensibility="medium"): # may add parameters
	    self.my_listtcp = list()
	    self.my_listudp = list()
	    self.ip_packet = list()
	    self.tcp_packet = list()
	    self.udp_packet = list()
	    self.endnode = node
	    self.totalpackets = 0
	    if sensibility == "high":
		self.sensibility = 50
	    elif sensibility == "medium":
		self.sensibility = 70
	    elif sensibility == "low":
		self.sensibility = 90
	    self.local_ip = ip # !!! Sometimes ip should be put manualy (when virtual machine use same real interface)
	    self.classic_detection=False
	    self.syn_scan=False
	    self.fin_scan=False
	    self.null_scan=False
	    self.ack_scan=False
	    self.xmas_scan=False
	    for element in scantype:
		if element == "classic":
		      self.classic_detection=True
		      break
		elif element == "syn_scan":
		      self.syn_scan=True
		elif element == "ack_scan":
		      self.ack_scan=True
		elif element == "null_scan":
		      self.null_scan=True
		elif element == "xmas_scan":
		      self.xmas_scan=True
		elif element == "fin_scan":
		      self.fin_scan=True
	
	
	def analyse(self, data):
		self.totalpackets += 1
		if isIP(data): #Quit if not ip packet
			self.ip_packet = getIPPacket(data)
		else:
			return
			
		if isTCP(self.ip_packet):
			#print "n°",self.totalpackets," TCP\r"
			self.tcp_packet = getTCPorUDPPacket(self.ip_packet)
		elif isUDP(self.ip_packet):
			#print "n°",self.totalpackets," UDP"
			self.udp_packet = getTCPorUDPPacket(self.ip_packet)
		else:
			return
		#From here we just manipulate TCP or UDP packet
	

		if self.endnode:
			if not getDstIp(self.ip_packet) == self.local_ip:
				return
		#for end node we just keep incoming connection
		#print "go in endnode", self.local_ip, " src:" , self.ip_packet.get_ip_src(), " dst:",self.ip_packet.get_ip_dst()
			
		if self.classic_detection:
			#In classic we don't care about flags (which are not reliable)
			if isTCP(self.ip_packet):
				self.processPacket(self.my_listtcp,getDstPortTCP(self.tcp_packet))
			elif isUDP(self.ip_packet):
				self.processPacket(self.my_listudp,getDstPortUDP(self.udp_packet))
		else:
			if isUDP(self.ip_packet):
				self.processPacket(self.my_listudp,getDstPortUDP(self.udp_packet))
				#UDP packet are process as in classic, because they don't have any flags
			else:
			    flag_dec_value = getDecFlagsValue(self.tcp_packet)
			    #using dec value of flag we can check that a flag is activated and be sure not the others
			    if (self.syn_scan and flag_dec_value == 2) or (self.ack_scan and flag_dec_value == 16) or (self.fin_scan and flag_dec_value == 1) or (self.null_scan and flag_dec_value == 0) or (self.xmas_scan and flag_dec_value == 41):
				self.processPacket(self.my_listtcp,getDstPortTCP(self.tcp_packet))
			    


	def processPacket(self, given_list,port):
		if self.endnode:
			suspect_ip = getSrcIp(self.ip_packet)
		else:
			suspect_ip = getDstIp(self.ip_packet)

		exist = False
		for i in range(len( given_list)):
			if given_list[i].getName() == suspect_ip:
				exist = True
				given_list[i].addPort(port)
				threatvalue =  given_list[i].calculateThreat_ratio()
		if not exist:
			new = SuspectHost(suspect_ip)
			given_list.append(new)
			new.addPort(port);
			threatvalue = new.calculateThreat_ratio()
		self.update_lists()
		self.checkThreat(suspect_ip, threatvalue,given_list)
	
	
	def update_lists(self):
		for i in range(len(self.my_listtcp)):
			if (time.time() - self.my_listtcp[i].getLastPacketDate()) > 300:
				#if the last packet of the host is older than 5 minutes
				del my_listtcp[i]
		for i in range(len(self.my_listudp)):
			if (time.time() - self.my_listudp[i].getLastPacketDate()) > 300:
				#if the last packet of the host is older than 5 minutes
				del my_listudp[i]
	
	
	def checkThreat(self,ip,threat,given_list):
		alert = False
		if threat >= self.sensibility: # If the threat calculated with all ports and their ponderation > sensibility
			for i in range(len(given_list)):
				if given_list[i].getName() == ip:
					if (len(given_list[i].getPorts())) > 10: # Updated to 10 (old was 3 and too much alert)
						if self.endnode:
							print datetime.now().strftime("%b %d, %H:%M:%S")," IP:%s is scanning with a threat of:%s and as scanned the following ports:" % (ip,threat)
						else:
							print datetime.now().strftime("%b %d, %H:%M:%S")," IP:%s is being scanned with a threat of:%s and the following ports are scanned" % (ip,threat)
						print given_list[i].getPorts(),"\n"
						del given_list[i]
						break