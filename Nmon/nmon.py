#!/usr/bin/python
# -*- coding: utf-8 -*-
'''
Nmon : Network Monitor
    ou
       Nmap Monitor
'''

__author__ = "Robin David"
__version__ = '0.1'

import sys
from datetime import datetime
import time
from multiprocessing import Queue
from Queue import Empty
import re
from HostsManager import HostsManager
from parser import parsestring, xml_to_dict


if sys.version_info[0] == 3 :
    import python3_nmap as nmap
else:
    import python2_nmap as nmap

try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process        



#monitored_hosts = dict()
dial_q = Queue()
run_process=None


#Core of the Process of run
def listen_request(external_q,internal_q): #sub thread of run, run into this function to listen requests
    while 1:
        req = external_q.get()
        if type(req) is list:
            if req[0] == "REPLY": #Mishandle a reply so send it back
                external_q.put(req)
            else:
                if req is not None:
                    internal_q.put(req)


def callback_nmon(host, scan_info, queue,output):#Function called by sub thread of PortScannerAsync when an event arrived
    if re.match(".*-sP.*",scan_info['nmap']['command_line']) :
        SCAN_TYPE="PING_SCAN"
    elif re.match(".*-sS.*",scan_info['nmap']['command_line']):
        SCAN_TYPE="TCP_SCAN"
    else:
        SCAN_TYPE="OTHER_SCAN"
    queue.put(["RES_SCAN",SCAN_TYPE, host, scan_info,xml_to_dict(parsestring(output))])

def run(network,request_q,verbose,i_ns,i_tcps,i_ps):
    
    interne_q = Queue()
    subproc = Process(target=listen_request, args=(request_q,interne_q))    
    subproc.daemon = True
    subproc.start()
    
    nma = nmap.PortScannerAsync()
    hostmanager = HostsManager(verbose)
    last_network_scan = time.time()
    nma.scan(hosts=network,arguments='-sP', callback=callback_nmon, queue=interne_q)#first scan

    while 1:
        try:
            req = None
            try:
                req = interne_q.get_nowait()
            except Empty:
                pass
            #-- deal with various kind of get results
            if req is None:
                pass
            else:
                if req[0] == "REQ_NBHOSTS":
                    #if verbose : print ("Receieved REQ_NBHOSTS")
                    request_q.put(["REPLY",len(hostmanager.getMonitoredHosts())])
                    
                elif req[0] == "REQ_MONHOSTS":
                    #if verbose: print ("Receieved REQ_MONHOSTS")
                    request_q.put(["REPLY",hostmanager.getMonitoredHosts()])
                
                elif req[0] == "REQ_LOGS":
                    request_q.put(["REPLY",hostmanager.getLogs()])
                    
                elif req[0] == "REQ_HOSTINFOS":
                    #if verbose: print ("Receieved REQ_HOSTINFOS")
                    try:
                        h = hostmanager.getMonitoredHosts()[req[1]]
                    except KeyError:
                        h = None
                    request_q.put(["REPLY",h])
     
                elif req[0] == "RES_SCAN":
                    #print ("RES_SCAN",req[1])
                    if req[1] == "PING_SCAN":
                        hostmanager.analyse_pingscan(req[2],req[3],req[4])
                    elif req[1] == "TCP_SCAN":
                        try:
                            hostmanager.analyse_tcpscan(req[2],req[3],req[4])
                        except KeyError:
                            pass#print("ERROR during this scan !")
                            #print req[4]
            time.sleep(0.1)
            #-----
            now = time.time()
            if now > last_network_scan + i_ns: #300: # dernier scan du reseau plus vieu que 5 minutes
                last_network_scan = now
                #n = nmap.PortScannerAsync()
                #if verbose: print("new network scan !")
                nmap.PortScannerAsync().scan(hosts='192.168.1.1-30',arguments='-sP', callback=callback_nmon, queue=interne_q)
            monitored_hosts = hostmanager.getMonitoredHosts()
            for host in monitored_hosts:
                
                if monitored_hosts[host].isUp():
                    #print("Ping scan:",monitored_hosts[host].getLastPing() +i_ps - now,monitored_hosts[host].getLastPing() +i_ps < now,' and ',not monitored_hosts[host].isBeingPing())
                    if monitored_hosts[host].getLastPing() +i_ps < now and not monitored_hosts[host].isBeingPing(): #120: #last ping since more than 2 mins
                        #if verbose: print("new ping scan for %s" % (host))
                        monitored_hosts[host].setPinging(True)
                        nmap.PortScannerAsync().scan(hosts=host,arguments='-sP', callback=callback_nmon, queue=interne_q)

                    #print("TCP scan: ",monitored_hosts[host].getLastScan() +i_tcps - now,monitored_hosts[host].getLastScan() +i_tcps < now," and ",not monitored_hosts[host].isBeingScanned())
                    if monitored_hosts[host].getLastScan() +i_tcps < now and not monitored_hosts[host].isBeingScanned(): #600: #1à minutes
                        #if verbose: print("new tcp scan for %s" % (host))
                        monitored_hosts[host].setScanning(True)
                        nmap.PortScannerAsync().scan(hosts=host,arguments='-sS -O --traceroute', callback=callback_nmon, queue=interne_q) # -A --traceroute                        
        except KeyboardInterrupt:
            break


#----------------------------------------------------

def runMonitorHandle(network,verbose=False,interval_networkscan=90,interval_tcpscan=60,interval_pingscan=30):
    run(network,Queue(),verbose,interval_networkscan,interval_tcpscan,interval_pingscan)

def runMonitor(network,verbose=False,interval_networkscan=90,interval_tcpscan=60,interval_pingscan=30):
    run_process = Process(target=run, args=(network,dial_q,verbose,interval_networkscan,interval_tcpscan,interval_pingscan))
    #run_process.daemon = True
    run_process.start()

#----- Available requests ----
def __get(req):
    dial_q.put(req)

def getNbHosts():
    dial_q.put(["REQ_NBHOSTS"])
    res = dial_q.get()
    return res[1]

def getMonitoredHosts():
    dial_q.put(["REQ_MONHOSTS"])
    res = dial_q.get()
    return res[1]

def getHostInfo(host):
    dial_q.put(["REQ_HOSTINFOS",host])
    res = dial_q.get()
    return res[1]

def getLogs():
    dial_q.put(["REQ_LOGS"])
    res = dial_q.get()
    return res[1]
#-------------------------

def stop():
    if run_process is not None:
        run_process.terminate()
    return
