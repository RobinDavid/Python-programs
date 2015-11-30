#!/usr/bin/python
# -*- coding: utf-8 -*-
#-----------------------------------#
	#Author: Robin David
	#Matriculation: 10014500
	#License: Creative Commons
#-----------------------------------#
import string
from impacket import ImpactDecoder, ImpactPacket #packet manipulation module

def getStringMac(mac_in):
    #Convert mac address from array to a string with ":" 
    joined_str = ''
    for i in xrange(5):
	joined_str += str(hex(mac_in[i])[2:])+":"
    return joined_str + hex(mac_in[5])[2:]
	
def getNameProtocolEthernet(proto_in):
	if proto_in == "0x800":
		return "IPv4"
	elif proto_in == "0x86DD":
		return "IPv6"
	elif proto_in == "0x806":
		return "ARP"
	elif proto_in == "0x8035":
		return "RARP"
	elif proto_in == "0x88CD":
		return "SERCOS III"
	elif proto_in == "0x8100":
		return "IEEE 802.1Q"
	elif proto_in == "0x8137":
		return "SNMP"
	elif proto_in == "0x880B":
		return "PPP"
	elif proto_in == "0x809B":
		return "AppleTalk"
	elif proto_in == "0x8137":
		return "NetWare IPX/SPX"
	else:
		return "Unknown"
	#there is lot's of others check :http://www.networksorcery.com/enp/protocol/802/ethertypes.htm

def getNameProtocolIP(proto_in):
	if proto_in == 1:
		return "ICMP"
	elif proto_in == 6:
		return "TCP"
	elif proto_in == 4:
		return "IPv4 Encapsulation"
	elif proto_in == 17:
		return "UDP"
	else:
		return "Unknown"
	#http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

def getNameApplicationTCP(port):
	if port == 80:
		return "HTTP"
	elif port == 21:
		return "FTP"
	elif port == 22:
		return "SSH"
	elif port == 23:
		return "telnet"
	elif port == 21:
		return "FTP"
	elif port == 53:
		return "DNS"
	elif port == 110:
		return "POP3"
	elif port == 143:
		return "IMAP"
	elif port == 389:
		return "LDAP"
	elif port == 443:
		return "HTTPS"
	elif port == 1863:
		return "MSNP"
	else:
		return "nc"
	#http://www.iana.org/assignments/port-numbers
	
def getFlagsString(URG,ACK,PSH,RST,SYN,FIN):
	st = ""
	if URG: st += "U"
	else:st += "-"
	
	if ACK: st += "A"
	else: st+= "-"
	
	if PSH: st += "P"
	else: st += "-"
	
	if RST: st += "R"
	else: st += "-"
	
	if SYN: st += "S"
	else: st += "-"
	
	if FIN: st += "F"
	else: st += "-"
	
	return st

def getDecFlagsValue(p):
	val=""
	if p.get_URG(): val +="1"
	else: val += "0"
	if p.get_ACK(): val +="1"
	else: val += "0"
	if p.get_PSH(): val +="1"
	else: val += "0"
	if p.get_RST(): val += "1"
	else: val += "0"
	if p.get_SYN(): val += "1"
	else: val += "0"
	if p.get_FIN(): val += "1"
	else: val += "0"
	return int(val,2)#return the value of val converted into base 2

def isIP(p):
	ether_packet = ImpactDecoder.EthDecoder().decode(p)
	eth_type = hex(ether_packet.get_ether_type())
	if getNameProtocolEthernet(eth_type) == "IPv4":
		return True
	else:
		return False

def getIPPacket(p):
	return ImpactDecoder.EthDecoder().decode(p).child()

def getTCPorUDPPacket(p):
	return p.child()

def isTCP(p):
	return getNameProtocolIP(p.get_ip_p()) == "TCP"

def isUDP(p):
	if getNameProtocolIP(p.get_ip_p()) == "UDP":
		return True
	else:
		return False

def getDstIp(p):
	return p.get_ip_dst()

def getSrcIp(p):
	return p.get_ip_src()

def getDstPortTCP(p):
	return p.get_th_dport()

def getDstPortUDP(p):
	return p.get_uh_dport()