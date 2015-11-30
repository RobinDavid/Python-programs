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
import re #regular expression
from email.parser import Parser #parser for mime type !
import time

class SuspectIP:
	def __init__(self,ip):
		self.ip = ip
		self.lastpacket_received = time.time()
		
		#all the different step
		self.step1_dns = False
		self.step2_https = False
		self.step3_home_request = False
		self.step4_answer = False
		self.chat_request = False
		self.chat_reply = False
		self.isauth = False
		
	def getIP(self):
		return self.ip
		
	def getLastPacketDate(self):
		return self.lastpacket_received
	
	def addValue(self, name,string):
		self.lastpacket_received = time.time()
		if name == "step1": self.step1_dns = True
		elif name == "step2": self.step2_https = True
		elif name == "step3": self.step3_home_request = True
		elif name == "step4":
			if self.step3_home_request and not self.step4_answer:
				print string # print message only if the request has been done before
				self.step4_answer = True
		elif name == "chat_q": self.chat_request = True
		elif name == "chat_r":
			if self.chat_request and not self.chat_reply:
				print string # print message only if the request has been done before
				self.chat_reply = True
		
	def authenticated(self):#return true if all steps are true
		if not self.isauth:
			if self.step2_https and self.step3_home_request and self.step4_answer:
				self.isauth = True
				return True
			else:
				return False
		else:
			return False
		#Note DNS request is exclud because not significant of authentication if the browser keep the ip in cache
	
	
	
class Facebook:
	def __init__(self):
		self.suspect_list = list()
		self.ip_packet = list()
		self.tcp_packet = list()
		
	def analyse(self, data):
		if isIP(data):
			self.ip_packet = getIPPacket(data)
		else:
			return #jump early to do not slowdown traffic
			
		if isUDP(self.ip_packet):
			self.test_step1_dns()

		elif isTCP(self.ip_packet):
			#All packet from here are normally TCP !
			self.tcp_packet = getTCPorUDPPacket(self.ip_packet)
			
			if self.tcp_packet.get_th_dport() == 443:
				self.test_step2_https()	
			elif self.tcp_packet.get_th_dport() == 80:
				self.test_step3_home_request()
				self.test_chat_request()
			elif self.tcp_packet.get_th_sport() == 80:
				self.test_step4_answer()
				self.test_chat_answer()
		self.update_list()


	def processPacket(self, ip, name,string=""):
		exist = False
		for suspect in self.suspect_list:
			if suspect.getIP() == ip:
				exist = True
				suspect.addValue(name,string)
				if suspect.authenticated() == True:
					  print "IP:",suspect.getIP()," seems fully authenticated on Facebook !"
		if not exist:
			new = SuspectIP(ip)
			new.addValue(name,string)
			self.suspect_list.append(new)


	def update_list(self):
		for i in range(len(self.suspect_list)):
			if (time.time() - self.suspect_list[i].getLastPacketDate()) > 180:
				#if the last packet of the host is older than 3 minutes
				print self.suspect_list[i].getIP()," reseted (facebook)"
				del self.suspect_list[i]
	
	
	def test_step1_dns(self):
		udp_packet = getTCPorUDPPacket(self.ip_packet)
		srcip = getSrcIp(self.ip_packet)
		#si double recup 3 ème charactère convertir en base 2 (see packet manager) et voir si le premier element et 0
		
		if getDstPortUDP(udp_packet) == 53:
			data = udp_packet.get_data_as_string()
			if re.search("www.facebook.com", data):
				print datetime.now().strftime("%b %d, %H:%M:%S")," IP:",srcip," DNS request for www.facebook.com"
				self.processPacket(srcip,"step1")
	


	def test_step2_https(self):
		ipsrc = getSrcIp(self.ip_packet)
		data = self.tcp_packet.get_data_as_string()
		if re.search("www.facebook.com", data):
			print datetime.now().strftime("%b %d, %H:%M:%S")," IP:",ipsrc," Possible HTTPS connection on www.facebook.com"
			self.processPacket(ipsrc,"step2")


	def test_step3_home_request(self):	
		srcip = getSrcIp(self.ip_packet)
		dstip = getDstIp(self.ip_packet)
		srcport = self.tcp_packet.get_th_sport()
		dstport = self.tcp_packet.get_th_dport()
		data = self.tcp_packet.get_data_as_string()
		new_data= data.split("\n",1)
		if len(new_data) >= 2:
			request = new_data[0]	#in theory in http taxonomy from client it is "command line" and from server it is "status line"
			raw_headers = new_data[1] 
			headers = Parser().parsestr(raw_headers,True) #true ignore payload
			if headers['Host'] == "www.facebook.com":
				if re.match("GET /home.php HTTP/1.1",request) or re.match("GET /update_security_info.php\?wizard=1 HTTP/1.1",request):
					print "%s %s:%s->%s:%s Facebook home page requested" % (datetime.now().strftime("%b %d, %H:%M:%S"),srcip,srcport,dstip,dstport)
					self.processPacket(srcip,"step3")


	def test_step4_answer(self):
		srcip = getSrcIp(self.ip_packet)
		dstip = getDstIp(self.ip_packet)
		srcport = self.tcp_packet.get_th_sport()
		dstport = self.tcp_packet.get_th_dport()
		data = self.tcp_packet.get_data_as_string()
		
		new_data= data.split("\n",1)
		if len(new_data) >= 2:
			request = new_data[0]
			raw_headers = new_data[1]
			headers = Parser().parsestr(raw_headers,True) #true ignore payload
			if not headers['Content-Type'] == None:
				if re.match("text/html",headers['Content-Type']) and re.match("HTTP/1.1 200 OK",request):
						to_print = "%s %s:%s->%s:%s Server reply: 200 OK" % (datetime.now().strftime("%b %d, %H:%M:%S"),srcip,srcport,dstip,dstport)
						#don't print the string here to avoid redundancy if buddy list request has not been done (and it is impossible to know it here)
						self.processPacket(dstip,"step4",to_print)
	
	
	def test_chat_request(self):
		srcip = getSrcIp(self.ip_packet)
		dstip = getDstIp(self.ip_packet)
		srcport = self.tcp_packet.get_th_sport()
		dstport = self.tcp_packet.get_th_dport()
		data = self.tcp_packet.get_data_as_string()
		new_data= data.split("\n",1)
		if len(new_data) >= 2:
			request = new_data[0]
			raw_headers = new_data[1] 
			headers = Parser().parsestr(raw_headers,True) #true ignore payload
			if headers['Host'] == "www.facebook.com":
				if re.search("POST /ajax/chat/buddy_list.php\?__a=1 HTTP/1.1",request):
					print "%s %s:%s->%s:%s Facebook contact chat list requested" % (datetime.now().strftime("%b %d, %H:%M:%S"),srcip,srcport,dstip,dstport)
					self.processPacket(srcip,"chat_q")


	def test_chat_answer(self):
		srcip = getSrcIp(self.ip_packet)
		dstip = getDstIp(self.ip_packet)
		srcport = self.tcp_packet.get_th_sport()
		dstport = self.tcp_packet.get_th_dport()
		
		data = self.tcp_packet.get_data_as_string()
		new_data= data.split("\n",1)
		if len(new_data) >= 2:
			request = new_data[0]
			raw_headers = new_data[1] 
			headers = Parser().parsestr(raw_headers,True) #true ignore payload
			if not headers['Content-Type'] == None:
				if re.match("application/x-javascript",headers['Content-Type']) and re.match("HTTP/1.1 200 OK",request):
					to_print = "%s %s:%s->%s:%s Server reply: 200 OK (for chat)" % (datetime.now().strftime("%b %d, %H:%M:%S"),srcip,srcport,dstip,dstport)
				#don't print the string here to avoid redundancy if buddy list request has not been done (and it is impossible to know it here)
					self.processPacket(dstip,"chat_r",to_print)