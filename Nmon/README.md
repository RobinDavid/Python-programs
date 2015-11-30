Nmon
====

Nmon is network monitor written in Python made as PoC for a University project about network scanning.

It is based on the Nmap python module. Nmon is provided as a python module with the aim to be used by anothers scripts or modules. The idea is to provide in real-time a map of the network. Indeed a script that use this module can know instantaneously the number of hosts up on the network theirs OS, uptime, MAC IP, open ports, distance the traceroute to them etc..

Basic usage ?
-------------

The module is mainly articulated around a modified version of python-nmap made by Alexandre Norman http://code.google.com/p/python-nmap/.
Indeed I needed to gather the hole nmap output MAC, OS, and services included whereas it is not possible for now.
So basically you just need to do the following.

    import nmon
    nmon.runMonitor(“192.168.0.*”)

Note: Change the IP to address to match you local network

So basically once you have done this two commands the monitor run in the background and monitor the network. At any time you can query it to get the network state available hosts etc.
The monitor maintain a list of hosts even if they disconnect of the network. This allow to know when an host has disconected for instance.
For a given host you can retrieve multiples informations like IP, MAC, OS, ports and services, uptime (basically all the informations that nmap can gather).
The network and hosts are regularly scanned, so this program create a really important packet throughput on the network. Be careful this module might
trigger some NIDS alerts.

Note: It seem's that python-nmap has been updated and using a custom is no longer needed (but some changes need to be done to match updates)

How it works
------------

First:

    import nmon
    nmon.runMonitor("192.168.0.*",verbose=False,interval_networkscan=90,interval_tcpscan=60,interval_pingscan=30)

So the facultatives arguments are:

* **verbose**: If set to True all events recorded will be printed on screen, like a new host connection, new port detected ..
* **interval_networkscan**: Define in seconds the interval of time between each complete network (for new host discovery)
* **interval_tcpscan**:  Define in seconds the interval of time between each tcp scan of a monitored host
* **interval_pingscan**: Define in seconds the interval of time between each ping scan of a monitored host

Once the monitor is launch the script that launched it get the handle back because the monitor is launch in another process, and it start to gather informations. I advice you to let the module gather informations a while at least 1 minute, otherwise the network map might be inaccurate.

Now the question is how to retrieve informations ?

The module provide various function to do it. They are :

* **getNbHosts()**: Return the number of monitored hosts and by the way the number of hosts on the network
* **getHostInfo(host)**: Return the information about the ip given in parameter in a string. The information returned is a Host class that contain everything about the host
* **getMonitoredHosts()**: Return a dictionnary of all monitored hosts indexed by theirs IPs
* **getLogs()**: Return all the events recorded by the module

_getHostInfo_ and _getMonitoredHosts_ return Host class objects. This class contains the following attributes:

* **ip** : Contain IP address in a String
* **name** : Name of the host, obtained by reverse DNS
* **mac** : Contain the MAC
* **os** : Contain the Operating System informations
* **uptime** : Contain a string of the uptime if detected
* **distance** : distance between you and the host
* **traceroute** : Contain a dictionnary of the route from you to the host
* **infos** : Contain informations related to ports
* **logs** : Contain all logs related to the host


