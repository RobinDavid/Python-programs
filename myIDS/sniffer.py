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

class AnalysePacket:
    def __init__(self):
	self.packet = 0
	
    def analyse(self, pack):
		self.packet = pack
		ether_packet = ImpactDecoder.EthDecoder().decode(self.packet) #Voir old
		
		eth_mac_destination = getStringMac(ether_packet.get_ether_dhost())
		eth_mac_source = getStringMac(ether_packet.get_ether_shost())

		eth_type = hex(ether_packet.get_ether_type())

		#others args
		#eth_header_size = str(ether_packet.get_header_size());
		#eth_datas = ether_packet.get_data_as_string();
		
		protocol=getNameProtocolEthernet(eth_type)
		
		#datetime.now().strftime("%H:%M:%S")
		print "\n\nEthernet:\tMAC src:%s\tMAC dst:%s\tEthertype:%s(%s)" % (''.join(eth_mac_source),eth_mac_destination,eth_type,protocol)
		
		if protocol=="IPv4":
			self.analyseIP(ether_packet);
		elif protocol=="ARP":
			pass
			#self.analyseARP(ether_packet)
		
    
    def analyseIP(self,ether):
		#For further informations:http://www.networksorcery.com/enp/default1101.htm
		#http://www.wikistc.org/wiki/Packet_crafting
		ip_packet = ether.child()
		
		ip_version = ip_packet.get_ip_v()	#ip version
		head_length = ip_packet.get_ip_hl()	# should be IHL for Internet Header Length
		tos = ip_packet.get_ip_tos()		# TOS field
		total_length = ip_packet.get_ip_len()	# field total length
		identification = ip_packet.get_ip_id()	# field identification of ip packet
		
		flag_rf = ip_packet.get_ip_rf()		# reserved flag
		flag_df = ip_packet.get_ip_df()		# flag don't fragment
		flag_mf = ip_packet.get_ip_mf()		# flag more fragmentation
		
		flag_off = ip_packet.get_ip_off()	# flag offset
		ttl = ip_packet.get_ip_ttl()		#TTL
		protocol = ip_packet.get_ip_p()		# protocol field
		header_checksum = ip_packet.get_ip_sum()# checksum field
		
		ip_source = ip_packet.get_ip_src()	# ip source
		ip_destination = ip_packet.get_ip_dst()	# ip destination
		
		'''
		others args
		ip_header_size = str(ip_packet.getheader_size());
		ip_datas = ip_packet.get_data_as_string();
		ip_offmask = ip_packet.get_ip_offmask() #should be to help processing of offset
		pseudo_header = ip_packet.get_pseudo_header(); #should be additional headers
		'''
		protocol_name=getNameProtocolIP(protocol)
		
		print "IPv%s:\tIP src:%s\tIP dst:%s\tProtocol:%s(%s)\tTTL:%s" % (ip_version,ip_source,ip_destination,protocol,protocol_name,ttl)
		
		if protocol_name == "TCP":
			self.analyseTCP(ip_packet)
		elif protocol_name == "ICMP":
			#self.analyseICMP(ip_packet)
			pass
		else:
			pass
		#for other protocol: http://www.networksorcery.com/enp/protocol/ip.htm
    
    
    def analyseTCP(self,ip):
		#for further info:http://www.networksorcery.com/enp/protocol/tcp.htm
		tcp_packet = ip.child()
		
		ecn_flag_CWR = tcp_packet.get_CWR()	#flag cwr for ECN: Explicit Congestion Notification
		ecn_flag_ECE = tcp_packet.get_ECE()	#flag ECE for ECN
		
		flag_URG = tcp_packet.get_URG()
		flag_ACK = tcp_packet.get_ACK()		#flag ack
		flag_PSH = tcp_packet.get_PSH()
		flag_RST = tcp_packet.get_RST()
		flag_SYN = tcp_packet.get_SYN()
		flag_FIN = tcp_packet.get_FIN()		#flag fin
		
		options = tcp_packet.get_options()	#field options
		port_dst = tcp_packet.get_th_dport()
		port_src = tcp_packet.get_th_sport()
		data_offset = tcp_packet.get_th_off()
		seq_num = tcp_packet.get_th_seq()
		ack_num = tcp_packet.get_th_ack()
		checksum = tcp_packet.get_th_sum()
		urgent_pointer = tcp_packet.get_th_urp()
		window = tcp_packet.get_th_win()
		
		'''
		other args
		get_flag(self, bit)
		get_header_size
		get_data_as_string
		get_packet() #return the entire packet !
		#others: get_padded_options, get_th_flags(may just return a string with all flags)
		'''
		name_portsrc = getNameApplicationTCP(port_src)
		name_portdst = getNameApplicationTCP(port_dst)
		flags = getFlagsString(flag_URG,flag_ACK,flag_PSH,flag_RST,flag_SYN,flag_FIN)
		# Print the results
		print "TCP: src port:%s\(%s)\tdst port:%s(%s)\tflags:%s\tSn:%s\tAn:%s\tWin:%s" % (port_src, name_portsrc,port_dst,name_portdst,flags,seq_num,ack_num,window)

    def analyseTCPOption(self,opt):
		opt=tcp_packet.get_options()
		for elt in opt:
			print "Kind:",elt.get_kind()
			print "Length:",elt.get_len()
			print "shift:",elt.get_shift_cnt()