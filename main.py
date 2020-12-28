#!/usr/bin/env python3

### Victor Plata
###
###
 
import sys
import struct
from kamene.all import *
from time import sleep
import random

global Seq
global Ack
Seq=23756
Ack=12343

def main():
    
    #Create values based on the config file
    global send
    send = False
    if sys.argv[1] == "-s":
        getConfig(sys.argv[2])
        send = True
    else:
        getConfig(sys.argv[1])

    #Create values based on the global header
    majorVer, minorVer, timeZone, timeAcc, maxSnapLen, linkLayer = readHeader(pcapFile)
    print('PCAP_MAGIC\nVersion major number = {}\nVersion minor number = {}\nGMT to local correction = {}'.format(majorVer, minorVer, timeZone) \
            +'\nTimestamp accuracy = {}\nSnaplen = {}\nLink type = {}'.format(timeAcc,maxSnapLen, linkLayer))

    packetNumber = 0
    for pkt_scapy in RawPcapReader(pcapFile):

        #Save the first timestamp for the relative timestamp value
        if packetNumber == 0:
            firstTime = int(pkt_scapy[2][0]) + int(pkt_scapy[2][1])/1000000
        timestamp = int(pkt_scapy[2][0]) + int(pkt_scapy[2][1])/1000000 - firstTime
        
        pkt = Ether(pkt_scapy[0])
        
        #Check if is an IP packet
        if pkt.type == 8 or pkt.type == 2048:
            #Check if matches the values to modify
            if pkt.getlayer(IP).src == orgSrcIp and orgVicIp == pkt.getlayer(IP).dst and pkt.src == orgSrcMac and pkt.dst == orgVicMac and str(pkt.getlayer(TCP).sport) == str(orgSrcPort) and str(pkt.getlayer(TCP).dport) == str(orgVicPort):
                #Check if is TCP
                if pkt.getlayer(IP).proto == 6:
                    printSendTcp(pkt, timestamp, packetNumber, pkt_scapy)
                #check if is UDP
                elif pkt.getlayer(IP).proto == 17:
                    printSendUdp(pkt, timestamp, packetNumber, pkt_scapy)
            #Check if matches values as a response
            elif pkt.getlayer(IP).src == orgVicIp and orgSrcIp == pkt.getlayer(IP).dst and pkt.src == orgVicMac and pkt.dst == orgSrcMac and str(pkt.getlayer(TCP).sport) == str(orgVicPort) and str(pkt.getlayer(TCP).dport) == str(orgSrcPort):
                #TCP
                if pkt.getlayer(IP).proto == 6:
                    printTcp(pkt, timestamp, packetNumber, pkt_scapy)
                #UDP
                elif pkt.getlayer(IP).proto == 17:
                    printUdp(pkt, timestampt, packetNumber, pkt_scapy)
        #ICMP
        elif pkt.getlayer(IP).proto == 1:
            printICMP(pkt, timestamp, packetNumber, pkt_scapy)
        #IGMP
        elif pkt.getlayer(IP).proto == 2:
            printIGMP(pkt, timestamp, packetNumber, pkt_scapy)
        #ARP
        elif pkt.type == 1544:
            printArp(pkt, timestamp, packetNumber, pkt_scapy)
        #OTHER
        else:
            printOther(pkt, timestamp, packetNumber, pkt_scapy)

        packetNumber += 1


### printSendTcp
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###     Send packet id flag -s is set
###
def printSendTcp(pkt, timestamp, packetNumber,pkt_scapy):
    global Seq
    global Ack
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport = newSrcMac, newVicMac, newSrcIp, newVicIp, int(newSrcPort), int(newVicPort)
    pkt.getlayer(TCP).seq = Ack
    pkt.getlayer(TCP).ack = Seq+1
    pkt.build()
    
    ip=IP(src=pkt.getlayer(IP).src,dst=pkt.getlayer(IP).dst) 
    payload = pkt.payload    
    tcp=TCP(sport=pkt.getlayer(TCP).sport,dport=pkt.getlayer(TCP).dport,flags=pkt.getlayer(TCP).flags,seq=Ack,ack=Seq+1) 
    
    responsePkt=pkt
    newPkt = (ip/tcp)
    newPkt.payload = payload
    #Checksum calculation
    del newPkt.chksum
    newPkt = newPkt.__class__(bytes(newPkt))
    
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgSrcMac,pkt.src, orgVicMac, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\trep_src = {}\n\tip_dst = {}\n\trep_dst = {}'.format(newPkt.getlayer(IP).len,orgSrcIp, newPkt.getlayer(IP).src, orgVicIp, newPkt.getlayer(IP).dst))
    print('\tTCP\n\t    Req Src Port = {}\n\t    Req Dst Port = {}\n\t    Seq = {}\n\t    Ack = {}'.format(newPkt.getlayer(TCP).sport, newPkt.getlayer(TCP).dport, newPkt.getlayer(TCP).seq, newPkt.getlayer(TCP).ack))


    
    #Sending Packetdepenging on delay and if -s flag set
    if send:
        if timing == "delay":
            responsePkt = sr1(newPkt, timeout=.5)
        elif timing == "continiuous":
            responsePkt = sr1(newPkt, timeout=.01)
        elif timing == "reactive":
            responsePkt = sr1(newPkt)
        elif timing == "exact":
            responsePkt = sr1(newPkt, timeout=timestamp)
            
    else:
        print("    Packet Not Sent")
    
    if(responsePkt is not None and TCP in responsePkt):
        Ack = responsePkt.ack
        Seq = responsePkt.seq



### printSendUdp
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###     Send packet id flag -s is set
###
def printSendUdp(pkt, timestamp, packetNumber,pkt_scapy):
    global Seq
    global Ack
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(UDP).sport, pkt.getlayer(UDP).dport = newSrcMac, newVicMac, newSrcIp, newVicIp, int(newSrcPort), int(newVicPort)
    pkt.getlayer(UDP).seq = Ack
    pkt.getlayer(UDP).ack = Seq+1
    pkt.build()

    ip=IP(src=pkt.getlayer(IP).src,dst=pkt.getlayer(IP).dst) 
    payload = pkt.payload    
    udp=UDP(sport=pkt.getlayer(UDP).sport,dport=pkt.getlayer(UDP).dport,flags=pkt.getlayer(UDP).flags,seq=Ack,ack=Seq+1) 
    responsePkt=pkt

    newPkt = (ip/udp)
    newPkt.payload = payload
    #Checksum calculation
    del newPkt.chksum
    newPkt = newPkt.__class__(bytes(newPkt))
    

    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgSrcMac,pkt.src, orgVicMac, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\trep_src = {}\n\tip_dst = {}\n\trep_dst = {}'.format(pkt.getlayer(IP).len,orgSrcIp, pkt.getlayer(IP).src, orgVicIp, pkt.getlayer(IP).dst))
    print('\tUDP\n\t    Req Src Port = {}\n\t    Req Dst Port = {}\n\t    Seq = {}\n\t    Ack = {}'.format(pkt.getlayer(UDP).sport, pkt.getlayer(UDP).dport, pkt.getlayer(UDP).seq, pkt.getlayer(UDP).ack))
 

    #Sending Packetdepenging on delay and if -s flag set
    if send:
        if timing == "delay":
            responsePkt = sr1(newPkt, timeout=.5)
        elif timing == "continiuous":
            responsePkt = sr1(newPkt, timeout=.01)
        elif timing == "reactive":
            responsePkt = sr1(newPkt)
        elif timing == "exact":
            responsePkt = sr1(newPkt, timeout=timestamp)
            
    else:
        print("    Packet Not Sent")
    
    if(responsePkt is not None and UDP in responsePkt):
        Ack = responsePkt.ack
        Seq = responsePkt.seq




#####################################END OF MAIN FUNCTION################################



### printTcp
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printTcp(pkt, timestamp, packetNumber,pkt_scapy):
    global Seq
    global Ack
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport = newVicMac, newSrcMac, newVicIp, newSrcIp, int(newVicPort), int(newSrcPort)
    pkt.build()
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgVicMac,pkt.src, orgSrcMac, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\trep_src = {}\n\tip_dst = {}\n\trep_dst = {}'.format(pkt.getlayer(IP).len,orgVicIp, pkt.getlayer(IP).src, orgSrcIp, pkt.getlayer(IP).dst))
    print('\tTCP\n\t    Req Src Port = {}\n\t    Req Dst Port = {}\n\t    Seq = {}\n\t    Ack = {}'.format(pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport, Seq, Ack))
    print('    Packet Not Send')


### printUdp
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printUdp(pkt, timestamp, packetNumber,pkt_scapy):
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport = newVicMac, newSrcMac, newVicIp, newSrcIp, int(newVicPort), int(newSrcPort)
    pkt.build()
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgVicMac,pkt.src, orgSrcMac, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\trep_src = {}\n\tip_dst = {}\n\trep_dst = {}'.format(pkt.getlayer(IP).len,orgVicIp, pkt.getlayer(IP).src, orgSrcIp, pkt.getlayer(IP).dst))
    print('\tTCP\n\t    Req Src Port = {}\n\t    Req Dst Port = {}\n\t    Seq = {}\n\t    Ack = {}'.format(pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport, pkt.getlayer(TCP).seq, pkt.getlayer(TCP).ack))
    print(' Packet Not Sent')


### printICMP
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printICMP(pkt, timestamp, packetNumber,pkt_scapy):
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport = newVicMac, newSrcMac, newVicIp, newSrcIp, int(newVicPort), int(newSrcPort)
    pkt.build()
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgVicMac,pkt.src, orgSrcMac, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\tip_dst = {}'.format(pkt.getlayer(IP).len, pkt.getlayer(IP).src, pkt.getlayer(IP).dst))
    print('\tICMP\n\t    {}'.format(pkt.getlayeri(ICMP).type))
    print('    Packet Not Send')


### printIGMP
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printIGMP(pkt, timestamp, packetNumber,pkt_scapy):
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    eth_dst = {}\n'.format(pkt.src, pkt.dst))
    print('    IP\n\tip_len = {}\n\tip_src = {}\n\tip_dst = {}'.format(pkt.getlayer(IP).len,pkt.getlayer(IP).src,pkt.getlayer(IP).dst))
    print('\tIGMP')
    print('    Packet Not Send')


### printArp
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printArp(pkt, timestamp, packetNumber,pkt_scapy):
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgVicMac,pkt.src, orgSrcMac, pkt.dst))
    print('    ARP\n\t{}'.format(pkt.getlayer(ARP).opcode))
    print('    Packet Not Send')


### printOther
### Param:
###     pkt - packet to be print
###     timestamp - pkt's timestamp
###     packetNumber - packetNumber
###     pkt_scapy - packet's info
###
### Purpose:
###     print packet's info
###
def printOther(pkt, timestamp, packetNumber,pkt_scapy):
    pkt.src, pkt.dst, pkt.getlayer(IP).src, pkt.getlayer(IP).dst, pkt.getlayer(TCP).sport, pkt.getlayer(TCP).dport = newVicMac, newSrcMac, newVicIp, newSrcIp, int(newVicPort), int(newSrcPort)
    pkt.build()
    print("\nPacket {}\n{:012.6f}\nCaptured Packet Length = {}\nActual Packet Length = {} \nEthernet Header".format(packetNumber,timestamp,pkt_scapy[2][2],len(pkt_scapy[0])))
    print('    eth_src = {}\n    rep_src = {}\n    eth_dst = {}\n    rep_dst = {}'.format(orgVicMac,pkt.src, orgSrcMac, pkt.dst))
    print('    Other')
    print('    Packet Not Send')


### getConfig
### Param:
###     fileName - config file name
### Purpose:
###     read config file
###
def getConfig(fileName):
    f=open(fileName,'r')
    line = f.readline().strip('\n')
    config = []
    while line:
        config.append(line)
        line = f.readline().strip('\n')
    global pcapFile
    global orgVicIp
    global orgVicMac
    global orgVicPort
    global orgSrcIp
    global orgSrcMac
    global orgSrcPort
    global newVicIp
    global newVicMac
    global newVicPort
    global newSrcIp
    global newSrcMac
    global newSrcPort
    global iFace
    global timing
    pcapFile, orgVicIp, orgVicMac, orgVicPort, orgSrcIp, orgSrcMac, orgSrcPort,  newVicIp, newVicMac, newVicPort, newSrcIp, newSrcMac, newSrcPort, iFace, timing = config
 
 
### readHeader
### Param:
###     filename - pcap file name
### Purpose:
###     get the global hedaer values
###
def readHeader(fileName):
    f=open(fileName, "rb")
    gHeader = f.read(24)
    magic = gHeader[:4]
 
    if magic == b"\xa1\xb2\xc3\xd4":  # big endian
        endian = ">"
    elif magic == b"\xd4\xc3\xb2\xa1":  # little endian
        endian = "<"
    elif magic == b"\xa1\xb2\x3c\x4d":  # big endian, nanosecond-precision
        endian = ">"
    elif magic == b"\x4d\x3c\xb2\xa1":  # little endian, nanosecond-precision  # noqa: E501
        endian = "<"
 
    vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(endian + "HHIIII", gHeader[4:])
    return vermaj, vermin, tz, sig, snaplen, linktype


main()

