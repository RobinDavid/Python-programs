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
import re #regular expression
from email.parser import Parser #parser for mime type !

from packet_function import *

	
class BBC:
	def __init__(self):
		self.ip_packet = list()
		self.tcp_packet = list()
		self.lastmessage = ""
		
	def analyse(self, data):
		if isIP(data):
			self.ip_packet = getIPPacket(data)
			
			if isTCP(self.ip_packet):
				self.tcp_packet = getTCPorUDPPacket(self.ip_packet)
				
				if self.tcp_packet.get_th_dport() == 1935:
					data = self.tcp_packet.get_data_as_string()

					if re.search("www..?bbc.c.?o.uk",data):		#if pattern found then try to pick up path of stream
						url_path = re.findall("(?!www\.bbc\/c.?o\.uk).*www\..?bbc\.co\.uk(.*)...$",data)[0]
						ip = getSrcIp(self.ip_packet)
						mess = "IP:%s\t Stream:www.bbc.co.uk%s" % (ip,url_path)
						if mess != self.lastmessage:	#avoid redundancy of message for same request and same ip
							print datetime.now().strftime("%b %d, %H:%M:%S"),mess
							self.lastmessage = mess