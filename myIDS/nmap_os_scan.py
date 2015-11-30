#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------#
	#Author: Robin David
	#Matriculation: 10014500
	#License: Creative Commons
#-----------------------------------#
import string
from impacket import ImpactDecoder, ImpactPacket #packet manipulation module
import pcapy
from datetime import datetime

from packet_function import *
import binascii
import time

class OSScan:
	def __init__(self,ip,sensibility="perfect"):
		self.ipfilter = ip
		self.ip_packet = list()
		self.nb_tests = 16
		self.firstT1packet = 0
		self.lastMatchingPacket = time.time()
		self.T1_complete = [False,False,False,False,False,False]
		self.ECN_complete = False
		self.IE1_complete = False
		self.IE2_complete = False
		self.U1_complete = False
		self.T2_complete = False
		self.T3_complete = False
		self.T4_complete = False
		self.T5_complete = False
		self.T6_complete = False
		self.T7_complete = False
		if sensibility == "perfect":
			self.sensibility = 100
		elif sensibility == "medium":
			self.sensibility = 90
		elif sensibility == "low":
			self.sensibility = 80
			
		
		
	def analyse(self, data, arrived_date):
		#http://www.networksorcery.com/enp/protocol/ip.htm
		#http://www.networksorcery.com/enp/protocol/tcp.htm
		
		if isIP(data): #Quit if not ip packet
			self.ip_packet = getIPPacket(data)
			#if getSrcIp(self.ip_packet) != self.ipfilter:
				#return
		else:
			return
		if getNameProtocolIP(self.ip_packet.get_ip_p()) == "TCP": #The same as isTCP function
		
			if self.T1match1() >= self.sensibility and not self.T1_complete[0]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #1 detected with an accuracy of: ", self.T1match1(),"%"
				self.T1_complete[0] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
				
			elif self.T1match2() >= self.sensibility and not self.T1_complete[1]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #2 detected with an accuracy of: ", self.T1match2(),"%"
				self.T1_complete[1] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
				
			elif self.T1match3() >= self.sensibility and not self.T1_complete[2]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #3 detected with an accuracy of: ", self.T1match3(),"%"
				self.T1_complete[2] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
				
			elif self.T1match4() >= self.sensibility and not self.T1_complete[3]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #4 detected with an accuracy of: ", self.T1match4(),"%"
				self.T1_complete[3] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
				
			elif self.T1match5() >= self.sensibility and not self.T1_complete[4]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #5 detected with an accuracy of: ", self.T1match5(),"%"
				self.T1_complete[4] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
				
			elif self.T1match6() >= self.sensibility and not self.T1_complete[5]:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T1 (Sequence Generation) Packet #6 detected with an accuracy of: ", self.T1match6(),"%"
				self.T1_complete[5] = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				self.T1OptionnalTest(arrived_date)
			#We have done all the check for the first six packets of T1
			
			elif self.ECNmatch() >= self.sensibility and not self.ECN_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," ECN Test (Explicit Congestion Notification) detected with an accuracy of: ", self.ECNmatch()
				self.ECN_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
			#And now all the test from T2 to T7
			
			elif self.T2match() >= self.sensibility and not self.T2_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T2 Test detected with an accuracy of: ", self.T2match()
				self.T2_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.T3match() >= self.sensibility and not self.T3_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T3 Test detected with an accuracy of: ", self.T3match()
				self.T3_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.T4match() >= self.sensibility and not self.T4_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T4 Test detected with an accuracy of: ", self.T4match()
				self.T4_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.T5match() >= self.sensibility and not self.T5_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T5 Test detected with an accuracy of: ", self.T5match()
				self.T5_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.T6match() >= self.sensibility and not self.T6_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T6 Test detected with an accuracy of: ", self.T6match()
				self.T6_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.T7match() >= self.sensibility and not self.T7_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," T7 Test detected with an accuracy of: ", self.T7match()
				self.T7_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
	
		elif getNameProtocolIP(self.ip_packet.get_ip_p()) == "ICMP":
		
			if self.IE1match() >= self.sensibility and not self.IE1_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," TCMP Echo(IE) Test #1 detected with an accuracy of: ", self.IE1match(),"%"
				self.IE1_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
			elif self.IE2match() >= self.sensibility and not self.IE2_complete:
				print datetime.now().strftime("%b %d, %H:%M:%S")," TCMP Echo(IE) Test #2 detected with an accuracy of: ", self.IE2match(),"%"
				self.IE2_complete = True
				self.getScore()
				self.lastMatchingPacket = arrived_date
				
		elif getNameProtocolIP(self.ip_packet.get_ip_p()) == "UDP":
			if not self.U1_complete:
				if self.U1match() >= self.sensibility:
					print datetime.now().strftime("%b %d, %H:%M:%S")," UDP Probe Test detected with an accuracy of: ", self.U1match(),"%"
					self.U1_complete = True
					self.getScore()
					self.lastMatchingPacket = arrived_date
		else:
			return

		self.updateTime()
		
	def updateTime(self):
		if time.time() > self.lastMatchingPacket + 120: #If we didn't received matching packed since 2 minutes
			#We put everything back to false
			self.lastMatchingPacket = time.time()
			for i in range(len(self.T1_complete)):
				self.T1_complete[i] = False
			self.ECN_complete = False
			self.IE1_complete = False
			self.IE2_complete = False
			self.U1_complete = False
			self.T2_complete = False
			self.T3_complete = False
			self.T4_complete = False
			self.T5_complete = False
			self.T6_complete = False
			self.T7_complete = False
			#print datetime.now().strftime("%b %d, %H:%M:%S")," Packets reset (Nmap OS scan)"
		
	def getScore(self):
		score = 0
		for i in self.T1_complete:
			if i == 1:
				score += 1
		if self.ECN_complete: score += 1
		if self.IE1_complete: score += 1
		if self.IE2_complete: score += 1
		if self.U1_complete: score += 1
		if self.T2_complete: score += 1
		if self.T3_complete: score += 1
		if self.T4_complete: score += 1
		if self.T5_complete: score += 1
		if self.T6_complete: score += 1
		if self.T7_complete: score += 1
		if score == self.nb_tests:
			print datetime.now().strftime("%b %d, %H:%M:%S")," !!!! BE CAREFUL a complete OS nmap scan has been detected !!!!"
		print "Out of: ",score,"/",self.nb_tests," packets detected\nNmap OS Scan with accuracy of: ",(score*100)/self.nb_tests,"%\n"

		
	def IE1match(self):
		'''
		The first one has the IP DF bit set, a type-of-service (TOS) byte value of zero, a code of
		nine (even though it should be zero), the sequence number 295, a random IP ID and ICMP request identifier,
		and 120 bytes of 0x00 for the data payload.
		Characteristics:
			- IP DF set
			- IP TOS of 0 for further check:http://www.networksorcery.com/enp/protocol/ip.htm#Differentiated Services
			- IP ID not used for tests (not significant)
			- Sn 295
			- ICMP echo ping request
			- ICMP code 0
			- Payload of 120 bytes of 0x00
		'''
		# Note TOS is obsolete now, but nmap still use Differentiated Services ip field as a TOS field RFC2474
		score = 0
		scoremax = 14
		if self.ip_packet.get_ip_df() != 0:
			score +=2
		if self.ip_packet.get_ip_tos() == 0:
			score +=1
		icmp_packet = self.ip_packet.child()
		if icmp_packet.get_icmp_code() == 9:
			score +=3
		if icmp_packet.get_icmp_seq() == 295:
			score +=3
		if icmp_packet.get_icmp_type() == 8:
			score +=1
		if len(icmp_packet.get_data_as_string()) == 120:
			score +=2
		buffer = '00'* 120
		if icmp_packet.get_data_as_string() == binascii.unhexlify(buffer):
			score +=2
		return (score*100) / scoremax
		
	def IE2match(self):
		'''
		The second ping query is similar, except a TOS of four (IP_TOS_RELIABILITY) is used, the code is zero,
		150 bytes of data is sent, and the ICMP request ID and sequence numbers
		are incremented by one from the previous query values.
		Characteristics:
			- echo ping request
			- No DF Set
			- Sn 296
			- IP TOS of 4
			- ICMP code 0 (which is normal)
			-Payload of 150 bytes
		'''
		score = 0
		scoremax = 13
		if self.ip_packet.get_ip_df() == 0:
			score +=1
		if self.ip_packet.get_ip_tos() == 4:
			score +=3
		icmp_packet = self.ip_packet.child()
		if icmp_packet.get_icmp_code() == 0:
			score +=1
		if icmp_packet.get_icmp_seq() == 296:
			score +=3
		if icmp_packet.get_icmp_type() == 8:
			score +=1
		if len(icmp_packet.get_data_as_string()) == 150:
			score +=2
		buffer = '00'* 150
		if icmp_packet.get_data_as_string() == binascii.unhexlify(buffer):
			score +=2
		return (score*100) / scoremax
		
		
	def U1match(self):
		'''
		This probe is a UDP packet sent to a closed port. The character ‘C’ (0x43) is repeated 300 times
		for the data field. The IP ID value is set to 0x1042 for operating systems which allow us to set this.
		If the port is truly closed and there is no firewall in place, Nmap expects to receive an ICMP port 
		unreachable message in return.
		Characteristics:
			- 'C' character 300 times in payload
			- IP ID 0x1042 -> 4162
		'''
		score = 0
		scoremax = 7
		if self.ip_packet.get_ip_id() == 4162:
			score +=3
		udp_packet=self.ip_packet.child()
		if len(udp_packet.get_data_as_string()) == 300:
			score +=2
		if udp_packet.get_data_as_string() == 'C'*300:
			score +=2
		return (score*100) / scoremax
		
	def ECNmatch(self):
		'''This probe tests for explicit congestion notification (ECN) support in the target TCP stack.
		ECN is a method for improving Internet performance by allowing routers to signal congestion problems
		before they start having to drop packets. It is documented in RFC 3168. Nmap tests this by sending a
		SYN packet which also has the ECN CWR and ECE congestion control flags set. For an unrelated (to ECN)
		test, the urgent field value of 0xF7F5 is used even though the urgent flag is not set. The acknowledgment
		number is zero, sequence number is random, window size field is three, and the reserved bit which
		immediately precedes the CWR bit is set. TCP options are WScale (10), NOP, MSS (1460), SACK permitted,
		NOP, NOP. The probe is sent to an open port.
		Characteristics:
			- SYN packet
			- ECN CWR and ECE flags set
			- URG Pointer value of OxF7F5 -> 63477
			- URG flag not set
			- An = 0
			- Sn random (so not significant)
			- Window size = 3
			- On the 3 bit of the reserved area the lower one is set
			- TCP options: WScale 10, NOP, MSS(1460), and SACK Permited, NOP, NOP'''
		score = 0
		scoremax=19
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_ECE():
			if tcp_packet.get_SYN():
				score += 1
			if tcp_packet.get_ECE():
				score += 2
			if tcp_packet.get_CWR():
				score += 2
			if tcp_packet.get_th_urp() == 63477:
				score += 3
			if not tcp_packet.get_URG():
				score += 1
			if tcp_packet.get_th_ack() == 0:
				score += 2
			if tcp_packet.get_th_win() == 3:
				score += 3
			opt = [3,3,10,1,2,4,5,180,4,2,1,1]#http://www.networksorcery.com/enp/protocol/tcp.htm#Options
			if tcp_packet.get_padded_options().tolist() == opt:
				score += 5
		return (score*100) / scoremax

	def T1match1(self):
		'''Packet #1: window scale (10), NOP, MSS (1460), 
		timestamp (TSval: 0xFFFFFFFF; TSecr: 0), SACK permitted. The window field is 1.'''
		score = 0
		scoremax=11
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 1:
			score +=3
		opt = [3,3,10,1,2,4,5,180,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax

	def T1match2(self):
		'''Packet #2: MSS (1400), window scale (0), SACK permitted, timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
		EOL. The window field is 63.'''
		score = 0
		scoremax=11
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 63:
			score +=3
		opt = [2,4,5,120,3,3,0,4,2,8,10,255,255,255,255,0,0,0,0,0]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax
		
	def T1match3(self):
		'''Packet #3: Timestamp (TSval: 0xFFFFFFFF; TSecr: 0), NOP, NOP, window scale (5),
		NOP, MSS (640). The window field is 4.'''
		score = 0
		scoremax=10
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 4:
			score +=2
		opt = [8,10,255,255,255,255,0,0,0,0,1,1,3,3,5,1,2,4,2,128]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax
		
	def T1match4(self):
		'''Packet #4: SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
		window scale (10), EOL. The window field is 4.'''
		#ip.src_host == 192.168.0.43 && tcp && tcp.window_size == 4 && tcp.options.wscale_val == 10 && not tcp.analysis.reused_ports && tcp.options.time_stamp == 0xffffffff
		score = 0
		scoremax=10
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 4:
			score +=2
		opt = [4,2,8,10,255,255,255,255,0,0,0,0,3,3,10,00]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax
		
	def T1match5(self):
		'''Packet #5: MSS (536), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0),
		window scale (10), EOL. The window field is 16.'''
		score = 0
		scoremax=11
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 16:
			score +=3
		opt = [2,4,2,24,4,2,8,10,255,255,255,255,0,0,0,0,3,3,10,00]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax
		
	def T1match6(self):
		'''Packet #6: MSS (265), SACK permitted, Timestamp (TSval: 0xFFFFFFFF; TSecr: 0). The window field is 512.'''
		score = 0
		scoremax=11
		tcp_packet=self.ip_packet.child()
		if tcp_packet.get_SYN():
			score += 1
		if len(tcp_packet.get_data_as_string()) == 0:
			score +=1
		#The two test above are in common with all T1 tests
		if tcp_packet.get_th_win() == 512:
			score +=3
		opt = [2,4,1,9,4,2,8,10,255,255,255,255,0,0,0,0]
		if tcp_packet.get_padded_options().tolist() == opt:
			#print tcp_packet.get_padded_options().tolist()
			score += 6
		return (score*100) / scoremax

	def T2match(self):
		#T2 sends a TCP null (no flags set) packet with the IP DF bit set and a window field of 128 to an open port.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,10,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() != 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 0:
			score += 6
		if tcp_packet.get_th_win() == 128:
			score +=3
		return (score*100) / scoremax

	def T3match(self):
		#T3 sends a TCP packet with the SYN, FIN, URG, and PSH flags set and a window field of 256 to an open port.
		#The IP DF bit is not set.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,10,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() == 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 43:
			score += 6
		if tcp_packet.get_th_win() == 256:
			score +=3
		return (score*100) / scoremax
		
	def T4match(self):
		#T4 sends a TCP ACK packet with IP DF and a window field of 1024 to an open port.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,10,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() != 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 16:
			score += 6
		if tcp_packet.get_th_win() == 1024:
			score +=3
		return (score*100) / scoremax
		
	def T5match(self):
		#T5 sends a TCP SYN packet without IP DF and a window field of 31337 to a closed port.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,10,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() == 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 2:
			score += 6
		if tcp_packet.get_th_win() == 31337:
			score +=3
		return (score*100) / scoremax

	def T6match(self):
		#T6 sends a TCP ACK packet with IP DF and a window field of 32768 to a closed port.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,10,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() != 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 16:
			score += 6
		if tcp_packet.get_th_win() == 32768:
			score +=3
		return (score*100) / scoremax

	def T7match(self):
		#T7 sends a TCP packet with the FIN, PSH, and URG flags set and a window field of 65535 to a closed port.
		#The IP DF bit is not set.
		score = 0
		scoremax=14
		tcp_packet=self.ip_packet.child()
		opt = [3,3,15,1,2,4,1,9,8,10,255,255,255,255,0,0,0,0,4,2]#Note: There is an exception T7 is not like the others
		if tcp_packet.get_padded_options().tolist() == opt:
			score +=3
			#they are less important than for T1 because T2-T6 got the sames options
		#The test above is in common with T2-T7
		if self.ip_packet.get_ip_df() == 0:
			score +=2
		if getDecFlagsValue(tcp_packet) == 41:
			score += 6
		if tcp_packet.get_th_win() == 65535:
			score +=3
		return (score*100) / scoremax
		
	def T1OptionnalTest(self,date_packet):
		begin=True
		end=True
		count =0
		for e in self.T1_complete:
			if not e: #if e not false
				end=False
			else:
				count +=1
		if count != 1: #if we are in this method it means a packet match so if count =1 it was the first
			begin=False
		if begin:
			self.firstT1packet = date_packet
		elif end:
			#print "T1 Complete :", date_packet - self.firstT1packet
			if date_packet - self.firstT1packet < 0.6 and date_packet - self.firstT1packet > 0.4:
				print "Anymore timing for T1 probes of 500ms match \n"
			#else:
			#	print " Does not match with :",date_packet - self.firstT1packet
		else:
			pass
