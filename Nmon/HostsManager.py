# -*- coding: utf-8 -*-
'''
Created on Dec 29, 2011

@author: root
'''
from Host import Host
from time import time
from datetime import datetime

class HostsManager():
    def __init__(self,verb):
        self.monitored_hosts = dict()
        self.verbose = verb
        self.logs = list()
        
    def analyse_pingscan(self,host,infos,output):
        if infos['nmap']['scanstats']['totalhosts'] != "1":
            print("Probleme avec le nombre d'hosts")
        elif infos['nmap']['scanstats']['totalhosts'] == "1":
            if infos['nmap']['scanstats']['uphosts'] == "1":
                if self.monitored_hosts.has_key(host):
                    self.monitored_hosts[host].setLastPing(time())
                    
                    if not self.monitored_hosts[host].isUp():
                        self.monitored_hosts[host].up = True
                        self.log(host,"is up")
                        
                    self.compareMacAddr(host, output) 
                    self.compareName(host, output)
                    
                    self.monitored_hosts[host].setPinging(False)
                else:
                    self.monitored_hosts[host]= Host(host,infos['scan'][host],time(),self.verbose)
                    self.log(host,"Detected !")
                    self.compareMacAddr(host, output)
            else: # is down
                if self.monitored_hosts.has_key(host):
                    self.monitored_hosts[host].setPinging(False)
                    self.monitored_hosts[host].up = False
                    self.log(host,"is down")
                    #self.monitored_hosts.pop(host) #remove host
    
    def compareMacAddr(self, host, output):
        if type(output['nmaprun']['host']['address']) is dict:
            #pass the address is obviously an ip address
            return
        else:
            for ad in output['nmaprun']['host']['address']:
                if ad['address']['addrtype'] == 'mac':
                    #print("In",ad['address'])
                    if self.monitored_hosts[host].mac is None:
                        if ad['address'].has_key('vendor'):
                            self.monitored_hosts[host].mac = {'vendor':ad['address']['vendor'],'addr':ad['address']['addr']}
                        else:
                            self.monitored_hosts[host].mac = {'vendor':'','addr':ad['address']['addr']}
                    else:
                        if not ad['address'].has_key('vendor'):
                            vendor = ""
                        else:
                            vendor = ad['address']['vendor']
                        if self.monitored_hosts[host].mac['vendor'] != vendor or self.monitored_hosts[host].mac['addr'] != ad['address']['addr']:
                            self.log(host,"Mac changed from %s(%s) to %s(%s)"%(self.monitored_hosts[host].mac['addr'],self.monitored_hosts[host].mac['vendor'],ad['address']['addr'],vendor))
                            self.monitored_hosts[host].mac = {'vendor':vendor,'addr':ad['address']['addr']}
    
    def compareOS(self, host, output):
        if type(output['nmaprun']['host']['os'].has_key('osclass')):
            if type(output['nmaprun']['host']['os']['osclass']) is dict:
                osclass= output['nmaprun']['host']['os']['osclass']
            else:
                osclass = output['nmaprun']['host']['os']['osclass'][0]['osclass'] # we take the more accurate which is the first
        else: osclass = {}
        
        if type(output['nmaprun']['host']['os'].has_key('osmatch')):
            if type(output['nmaprun']['host']['os']['osmatch']) is dict:
                osmatch= output['nmaprun']['host']['os']['osmatch']
            else:
                osmatch = output['nmaprun']['host']['os']['osmatch'][0]['osmatch'] # we take the more accurate which is the first
        else: osmatch = {}
        
        os = {'osclass':osclass,'osmatch':osmatch}
        if self.monitored_hosts[host].os is None:
            self.monitored_hosts[host].os = os
        else:
            if self.monitored_hosts[host].os['osclass'] != os['osclass']:
                self.log(host,"Os class changed From %s To %s" % (self.monitored_hosts[host].os['osclass'], os['osclass']))
                self.monitored_hosts[host].os['osclass'] = os['osclass']
            if self.monitored_hosts[host].os['osmatch'] != os['osmatch']:
                self.log(host,"Os match changed From %s To %s" % (self.monitored_hosts[host].os['osmatch'], os['osmatch']))
                self.monitored_hosts[host].os['osmatch'] = os['osmatch']

    def compareUptime(self, host, output):
        if output['nmaprun']['host'].has_key('uptime'):
            up = output['nmaprun']['host']['uptime']['lastboot']
            if self.monitored_hosts[host].uptime is None:
                self.monitored_hosts[host].uptime = up
            else:
                if self.monitored_hosts[host].uptime != up:
                    self.log(host,"Uptime changed From '%s' To '%s'" %(self.monitored_hosts[host].uptime,up))
                    self.monitored_hosts[host].uptime = up
    
    def compareDistance(self,host, output):
        if output['nmaprun']['host'].has_key('distance'):
            dist = output['nmaprun']['host']['distance']['value']
            if self.monitored_hosts[host].distance is None:
                self.monitored_hosts[host].distance = dist
            else:
                if self.monitored_hosts[host].distance != dist:
                    self.log(host,"Distance changed From %s To %s" % (self.monitored_hosts[host].distance,dist))
                    self.monitored_hosts[host].distance = dist
    
    def compareTraceroute(self,host, output):
        if output['nmaprun']['host'].has_key("trace"):
            trace = output['nmaprun']['host']['trace']['hop']
            if type(trace) is dict:
                trace = [{'hop':trace}] #convert the single element to list
            if self.monitored_hosts[host].traceroute is None:
                self.monitored_hosts[host].traceroute = trace
            else:
                actual = self.monitored_hosts[host].traceroute
                for old, new in zip(actual,trace):
                    if old['hop']['ipaddr'] != new['hop']['ipaddr']:
                        self.log(host," Hop n°%s changed From %s To %s "%(new['hop']['ttl'],actual['hop']['ipaddr'],new['hop']['ipaddr']))
                self.monitored_hosts[host].traceroute= trace
    
    def compareName(self, host, output):
        if output['nmaprun']['host']['hostnames'].has_key("hostname"):
            hostname = output['nmaprun']['host']['hostnames']['hostname']
            if type(hostname) is dict:
                hostname = [{'hostname':hostname}]
            names = list(set([x['hostname']['name'] for x in hostname ]))
            names.sort()
            if self.monitored_hosts[host].name is None:
                self.monitored_hosts[host].name = names # RETIRER doublons !
            else:
                actual = self.monitored_hosts[host].name
                for old, new in zip(actual, names):
                    if old != new:
                        self.log(host," Name changed From %s To %s "%(old,new))
                self.monitored_hosts[host].name = names
        else:
            pass#print("no hostname",output['nmaprun']['host']['hostnames'])

    def compareTCP(self,host,infos, output):
                    #Comparaison des nouvelles donnees TCP avec les anciennes
                    current = self.monitored_hosts[host].getInfos()
                    new = infos['scan'][host]
                    if current.has_key('tcp'):
                        if current['hostname'] != new['hostname']:
                            self.log(host,"hostname has changed from %s to %s" % (current['hostname'],new['hostname']))
                        for port in new['tcp']:
                            if current['tcp'].has_key(port):
                                if current['tcp'][port]['state'] != new['tcp'][port]['state']:
                                    self.log(host,"Port %s state has changed from %s to %s" % (port,current['tcp'][port]['state'],new['tcp'][port]['state']))
                                current['tcp'].pop(port)
                            else: #nouveau port
                                self.log(host,"New port (%s) detected" % (port))
                        for port in current['tcp']:
                            # normalement il ne reste que ceux qui on ete fermes !
                            self.log(host,"Port %s is now closed" % (port))
                    else:
                        #Nouveau scan !
                        self.log(host,"First port scan done")
                    self.monitored_hosts[host].updateInfos(new)
                    #----------------------------------        
    
    def analyse_tcpscan(self,host,infos,output):
        if infos['nmap']['scanstats']['totalhosts'] != "1":
            print("Probleme avec le nombre d'hosts")
        elif infos['nmap']['scanstats']['totalhosts'] == "1":
            if infos['nmap']['scanstats']['uphosts'] == "1":
     
                if self.monitored_hosts.has_key(host):
                    if not self.monitored_hosts[host].isUp():
                        self.monitored_hosts[host].up = True
                        self.log(host,"is up")
                    
                    self.compareTCP(host,infos, output)
                    self.compareMacAddr(host,output)   
                    self.compareOS(host,output)
                    self.compareUptime(host, output)
                    self.compareDistance(host, output)
                    self.compareTraceroute(host, output)
                    self.compareName(host, output)
                    self.monitored_hosts[host].setLastScan(time())
                    self.monitored_hosts[host].setScanning(False)
                else:
                    pass # impossible qu'on ai fait un tcp scan sur un host qui n'est pas dans le dictionnaire
                    
            else: # is down
                if self.monitored_hosts.has_key(host):
                    self.monitored_hosts[host].setScanning(False)
                    self.monitored_hosts[host].up = False
                    self.log(host,"is down")
    
    def getMonitoredHosts(self):
        return self.monitored_hosts
    
    def getLogs(self):
        return self.logs
    
    def log(self,host,mess):
        date = datetime.now()
        s = "%s - %s - %s" %(date.strftime("%b %d %H:%M:%S"),host,mess)
        self.logs.append(s)
        if self.verbose: print (s)
        self.monitored_hosts[host].log(date, mess)