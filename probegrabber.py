#! /usr/bin/env python
import os, time,sys
from subprocess import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

SCAN_TIME = 30 # Number of seconds to sniff (update frequency)
unique_probe = []
unique_mac = []


def Handler(pkts):
	for p in pkts:
	 try:
	  null = p.subtype
	 except:
	  p = p.payload
	 else:
		 if (p.subtype == 4L):
			mac = p.addr2
			while Dot11Elt in p:
			 pa = p[Dot11Elt]
			 if pa.ID == 0:
			  ssid = pa.info
			  if (ssid != ""):
			   print "Found probe: " + ssid
			   if ssid not in unique_probe:
			    unique_probe.append(ssid)
			    if mac not in unique_mac:
			     unique_mac.append(mac)
			  break
			 p = p.payload


def printUsage():
	print "Usage: %s num_seconds_to_scan scan_channel(1-13)" % sys.argv[0]


if __name__ == "__main__":
	if len(sys.argv) < 3:
		printUsage()
		sys.exit(0)
	SCAN_TIME = float(sys.argv[1])
	
	channel = sys.argv[2]
	print "Scanning for probes on channel " + channel + " for %s seconds" % sys.argv[1]
	p = Popen("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " +"sniff " + channel, shell=True)
	time.sleep(SCAN_TIME)
	Popen("kill -HUP %s" % p.pid, shell=True)
	search_dir = "/tmp/"
	os.chdir(search_dir)
	files = filter(os.path.isfile, os.listdir(search_dir))
	files = [os.path.join(search_dir, f) for f in files] # add path to each file
	files.sort(key=os.path.getmtime, reverse=True)
	if os.path.getsize(files[0]) < 1:
	 print "No wifi traffic found on this channel"
	 sys.exit(0)
	print "Checking pcap file "+ files[0]
	
	print "\r\nWorking to find probes in pcap"
	sniff (offline=files[0],prn=Handler,filter="subtype 4")
	print "\r\n\r\nUnique list of SSID probes:"
	for ssid in unique_probe:
	 print ssid
	print "\r\n\r\nUnique list of MAC addresses probing:"
	for mac in unique_mac:
	 print mac
