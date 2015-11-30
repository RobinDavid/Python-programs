# -*- coding: utf-8 -*-
'''
Created on Dec 28, 2011

@author: Robin David
'''
from time import time
from datetime import datetime

class Host():
    def __init__(self, ip, infos, ping,verb=False):
        self.last_ping = ping
        self.last_scan = 0 #to be sure it will be scanned right after
        self.isScanned = False
        self.isPing = False
        self.verbose=verb
        
        # Informations
        self.infos = infos
        self.ip = ip
        self.name = None
        self.mac = None
        self.up = True
        self.os = None
        self.uptime = None
        self.distance = None
        self.traceroute= None
        
        self.logs = list()
    
    def log(self, date, infos):
        self.logs.append("%s - %s" % (date.strftime("%b %d %H:%M:%S"), infos))
        
    def getLastPing(self):
        return self.last_ping
    
    def setLastPing(self, val):
        self.last_ping = val
        #if self.verbose: print("Last ping changed for %s" %(self.ip))
        
    def getLastScan(self):
        return self.last_scan
    
    def setLastScan(self, val):
        self.last_scan = val
        #if self.verbose: print("Last scan changed for %s" %(self.ip))
        
    def getInfos(self):
        return self.infos
    
    def updateInfos(self, infos):
        self.infos = infos
        
    def isBeingScanned(self):
        return self.isScanned
    
    def isBeingPing(self):
        return self.isPing
    
    def setPinging(self,val):
        self.isPing=val
    def setScanning(self,val):
        self.isScanned=val
        
    def isUp(self):
        return self.up