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
import time
from packet_function import *
import re #regular expression
from email.parser import Parser #parser for mime type !



class Triplet:
	def __init__(self, port_nb):
		self.port = port_nb
		self.packet_list = list() #list of the date of the reception of the 3 packets !
	
	def getPortName(self):
		return self.port
	
	def getIndex(self):
		return len(self.packet_list)-1
		
	def addElement(self,time):
		if len(self.packet_list) < 3:
			self.packet_list.append(time)
	
	def getElement(self,i):
		return self.packet_list[i]


class SuspectIP:
	def __init__(self,ip,time):
		self.ip = ip
		self.nbpacket = 0
		self.triplet_list = list()	#List of triplet (normally maximum 10 triplets (3*10))
		self.firstpacket_received = time
		self.lastpacket_received = 0
		
	def getIP(self):
		return self.ip
		
	def getLastPacketDate(self):
		return self.lastpacket_received
	
	def addPacket(self,port,time_recep):
		self.lastpacket_received = time_recep
		exist = False
		for i in range(len(self.triplet_list)):				#check all element of the list of suspect
			if self.triplet_list[i].getPortName() == port:	#if already in the list
				exist = True
				cur = self.triplet_list[i]
				cur.addElement(time_recep)	#add element to the triplet
				index = cur.getIndex()
				self.nbpacket += 1
				print datetime.now().strftime("%b %d, %H:%M:%S"),"IP:%s Port:%s(%s/3) BOTNET packet Date:%s(difference:%s) Total count:%s" %	(self.ip,cur.getPortName(),index+1, datetime.fromtimestamp(cur.getElement(index)).strftime("%H:%M:%S"), cur.getElement(index) - cur.getElement(index-1),self.nbpacket)
				if self.nbpacket == 30:
					print datetime.now().strftime("%b %d, %H:%M:%S"),"IP:%s all packet from botnet signature detected in %s seconds" % (self.ip, self.lastpacket_received - self.firstpacket_received)
		if not exist:
			new = Triplet(port)		#Creation of the new suspect and push it in the list
			new.addElement(time_recep)
			self.nbpacket += 1
			self.triplet_list.append(new)
			print datetime.now().strftime("%b %d, %H:%M:%S"),"IP:%s Port:%s(1/3) BOTNET packet Date:%s Total count:%s" % (self.ip,port,datetime.fromtimestamp(time_recep).strftime("%H:%M:%S"),self.nbpacket)
	
	
#--------------------#	
   # Class Botnet #
#--------------------#	
class botnet:
	def __init__(self):
		self.ip_packet = list()
		self.tcp_packet = list()
		self.suspect_list = list()
		
	def analyse(self, data,time_recep):
		if isIP(data):
			self.ip_packet = getIPPacket(data)
			srcip = getSrcIp(self.ip_packet)
			
			if isTCP(self.ip_packet):
				self.tcp_packet = getTCPorUDPPacket(self.ip_packet)
	
				if self.tcp_packet.get_th_dport() == 1013 and getDstIp(self.ip_packet) == "192.168.5.13" and getDecFlagsValue(self.tcp_packet) == 2: #if the packet matches all requirements
					self.processPacket(srcip,self.tcp_packet.get_th_sport(),time_recep)
		self.update_list()

					
	def processPacket(self, ip,port,rec_time):
		exist = False
		for suspect in self.suspect_list:
			if suspect.getIP() == ip:
				exist = True
				suspect.addPacket(port,rec_time)
		if not exist:
			new = SuspectIP(ip,rec_time)
			new.addPacket(port,rec_time)
			self.suspect_list.append(new)

	def update_list(self):
		for i in range(len(self.suspect_list)):
			if (time.time() - self.suspect_list[i].getLastPacketDate()) > 240:
				#if the last packet of the host is older than 4 minutes
				print self.suspect_list[i].getIP()," reseted (botnet)"
				del self.suspect_list[i]