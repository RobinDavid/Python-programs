myIDS
=====

myIDS as a basic NIDS developed for an university project in python.
The program needed to be able to detect to following event:

* A facebook connection (and login ids if possible)
* An nmap OS scan
* A port scan
* A bbc streaming access
* A connection to msn

Note: myIDS can also act as a sniffer an log every events
Note: This program was firstly upload to http://code.google.com/p/10014500-myids/

Requirements
------------

The two main requirements to run myIDS is pcapy, and impacket which all to sniff the network and decode all the packets. They are available in most Linux distribution packages, but for Windows users you will certainly need to compile them by hand.
