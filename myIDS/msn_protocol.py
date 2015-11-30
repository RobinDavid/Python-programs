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

class MSN:
	def __init__(self,ip, parano=False):
		self.local_ip = ip
		self.ip_packet = list()
		self.tcp_packet = list()
		self.paranoid_mode = parano #will determine if all tcp packets are examined or just dst.port=1863
		
	def analyse(self, data):
		if isIP(data):
			self.ip_packet = getIPPacket(data)
		else:
			return #jump early to do not slow down traffic
			
		if isUDP(self.ip_packet):
			udp_packet = getTCPorUDPPacket(self.ip_packet)
			
			if getDstPortUDP(udp_packet) == 53:
				data = udp_packet.get_data_as_string()
				if re.search("login.live.com", data):
					print datetime.now().strftime("%b %d, %H:%M:%S")," DNS request for login.live.com"
				elif re.search("messenger.hotmail.com", data):
					print datetime.now().strftime("%b %d, %H:%M:%S")," DNS request for messenger.hotmail.com"
				elif re.search("g.live.com", data):
					print datetime.now().strftime("%b %d, %H:%M:%S")," DNS request for g.live.com"
			pass
		elif isTCP(self.ip_packet):
			#All packet from here are normally TCP !
			self.tcp_packet = getTCPorUDPPacket(self.ip_packet)
			
			if self.tcp_packet.get_th_dport() == 80 or self.tcp_packet.get_th_sport() == 80:
				return
				#Directly skip all http traffic to avoid useless processing on it because we are not interested in 
			elif self.tcp_packet.get_th_dport() == 443 and getDecFlagsValue(self.tcp_packet) == 2:
				#If we try to connect on a website in https, syn flags to trigger alarm once per connection(if it is)
				if self.test_https_auth():
					print datetime.now().strftime("%b %d, %H:%M:%S")," Connection on a HTTPS MSN Server (maybe to pick up a authentication ticket)" 
			elif self.tcp_packet.get_th_dport() == 1863 or self.tcp_packet.get_th_sport() == 1863:
				self.test_msn_connection()
				self.test_file_transfert()
			elif self.paranoid_mode:
				self.test_file_transfert()
			else:
				pass
		else:
			pass
	
	def test_https_auth(self):
		dst_ip = getDstIp(self.ip_packet)
		msn_servers = ['65.54.165.137','65.54.165.141','65.54.165.139','65.54.165.169','65.54.165.179','65.54.186.77','65.54.165.136','65.54.165.177']
		isMSNserver = False
		#determined with an nslookup should be updated if needed
		for ip in msn_servers:
			if dst_ip == ip:
				isMSNserver = True
		return isMSNserver
		
	def test_msn_connection(self):
		data = self.tcp_packet.get_data_as_string()
		
		if getDecFlagsValue(self.tcp_packet) == 2:
			print "\n",datetime.now().strftime("%b %d, %H:%M:%S")," New Connection on the TCP 1863 (which can be a MSN notification server)!"
			
		if re.match("VER 1 ",data):
			#VER 1 MSNP21 MSNP20 MSNP19 MSNP18 MSNP17 CVR0
			#VER 1 MSNP21
			if getSrcIp(self.ip_packet) == self.local_ip:
				print datetime.now().strftime("%b %d, %H:%M:%S")," VER Step detected Client->Server (Protocol version exchange)"
			else:
				print datetime.now().strftime("%b %d, %H:%M:%S")," VER Step detected Server->Client (Version %s used)" % (data[6:12])
				
		elif re.match("CVR 2 ",data):
			#CVR 2 0x0409 winnt 6.1.0 i386 MSNMSGR 15.4.3502.0922 MSNMSGR me@hotmail.fr 
			#VmVyc2lvbjogMQ0KWGZyQ291bnQ6IDENCg==
			if getSrcIp(self.ip_packet) == self.local_ip:
				print datetime.now().strftime("%b %d, %H:%M:%S")," CVR Step detected Client->Server (client information sent)"
				infos = data[6:].split(" ")
				print "\t\tLocale:%s\tOS:%s(%s)\tArchi:%s\tClient:%s(%s)\tAddress:%s" % (infos[0],infos[1],infos[2],infos[3],infos[4],infos[5],infos[7])
				#Further about locale :http://krafft.com/scripts/deluxe-calendar/lcid_chart.htm
			else:
				print datetime.now().strftime("%b %d, %H:%M:%S")," CVR Step detected Server->Client (Stored client information received)"
				
		elif re.match("USR 3 ",data):
			#USR 3 SSO I me@hotmail.fr
			#alert user send the initiation message of authentication
			infos = data.split(" ")
			print datetime.now().strftime("%b %d, %H:%M:%S")," USR Step detected (Initiation authentication) method:%s\tAddress:%s" % (infos[2],infos[4])
			
		elif re.match("USR 4 ",data) and not re.match("USR 4 OK ",data):
			# USR 4 SSO S t=E (s for subsequent and the ticket attached)
			#Note SSO was not used to match because I don't know but, may other methods exists
			print datetime.now().strftime("%b %d, %H:%M:%S")," USR Step detected (Ticket/Token dispatching)"
			
		elif re.match("USR 4 OK ",data):
			#USR 4 OK me@hotmail.fr 1 0
			infos= data.split(" ")
			print datetime.now().strftime("%b %d, %H:%M:%S")," Address %s connected and authenticated to msn !" % (infos[3])
		
	def test_file_transfert(self):
		data = self.tcp_packet.get_data_as_string()
		new_data = ["",data]
		if re.search("INVITE",data):#keep only invitation message
			notFound = True
			while notFound: #separate first line from the rest and delete useless \n before
				new_data = new_data[1].split("\n",1)
				if re.search("INVITE",new_data[0]):
					notFound = False
		else:
			pass
			
		#First element in the array contain invitation message
		#The second contain mime elements
		#should do this, because otherwise the mime parsing fail due to the first line which is not mime
		if len(new_data) >= 2:#otherwise parsing below can fail due to out of range
			
			new_data[1] = re.sub(r'\r\n\r\n','\r\n',new_data[1])
			mime_elts = Parser().parsestr(new_data[1],True) # parse the packet as mime type (True means ignore payload)
			#So to get payload remove True, and it is accessible with mime_elts.get_payload()
			
			
			if mime_elts['EUF-GUID'] == "{5D3E02AB-6190-11D3-BBBB-00C04F795683}": #This is signature of file transfert !
				if re.search("INVITE",new_data[0]):#if it was really an invitation
					print "\n",datetime.now().strftime("%b %d, %H:%M:%S")," File transfer invitation !"
					print "\t\tFrom:%s\n\t\tTo:%s" % (mime_elts['From'],mime_elts['To'])
					
					#additional tests
					if mime_elts['CSeq'] == "0 " or mime_elts['CSeq'] == "0":#windows live put a space other client not
						print "\t\tAnymore CSeq = 0 (file transfer signature)"
					if mime_elts['appID'] == '2':
						print "\t\tAnymore AppID = 2 (file transfer signature)"
					if mime_elts['Content-Type'] == "application/x-msnmsgr-sessionreqbody":
						print "\t\tAnymore Content-Type = application/x-msnmsgr-sessionreqbody (file transfer signature)\n"
					