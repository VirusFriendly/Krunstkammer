# nmap-scripts
My personal collection of Nmap scripts and tools

## sf-signatures
I am a hunter of unknown (at least to me) protocols, this is where I keep the service fingerprints of new protocols I come across for future research.

## nse-scripts
Largely insignificant nse scripts I made, mainly for the purpose of getting used to the nse api. Perhaps in the future I'll make more significant scripts.

## parse_fingerprint module
This is probably the reason you're looking at this repo. If you have a Nmap OS or Service fingerprint, this module will clean it up and give you and information dump of what was in the fingerprint.

Its a module, so if you don't like the report format, you can still use the parser and have it formatted anyway you like.

If there's interest maybe I'll add a method for exporting it as xml or json.

### Example Output
**Service Fingerprint**

    # NMAP Service Fingerprint
    Nmap Version: 7.60
    Platform: x86_64-pc-linux-gnu
    Date: March 19 08:10:25
    I=7
    Probe-Responces:
    |  GetRequest, FourOhFourRequest:
    |    HTTP/1\.1 401 Unauthorized
    |    Content-Length: 45
    |    Content-Type: application/json
    |    Date: Thu, 19 Mar 2020 13:45:48 GMT
    |    Connection: close
    |    
    |    {"code":0,"message":"Authorization Required"}
    |  HTTPOptions:
    |    HTTP/1\.1 200 OK
    |    Content-Length: 11
    |    Content-Type: application/json
    |    Date: Thu, 19 Mar 2020 13:45:48 GMT
    |    Connection: close
    |    
    |    {"body":""}
    |  RTSPRequest, RPCCheck, DNSVersionBindReq, DNSStatusRequest, Help, SSLSessionReq, TLSSessionReq, Kerberos, SMBProgNeg, X11Probe, LPDString, LDAPSearchReq, LDAPBindReq, SIPOptions, LANDesk-RC:
    |    HTTP/1\.1 400 Bad Request
    |    Connection: close
    |    

**OS Fingerprint**

    # NMAP OS Fingerprint
    Scanline (SCAN)
      Nmap Version: 7.60
      Platform: x86_64-pc-linux-gnu
      Date: March 19 08:10:25
      E=4
      TCP Ports: 80 open, 1 closed.
      Closed UDP Ports: 40536.
      Target was on a private network.
      Target was on the local network, and had a MAC prefix of 681401.
      This OS Fingerprint is acceptible for submission.
    Sequence Generation 1 (SEQ)
      SP=106 : ISN Sequence Predictibily Index: 262
      GCD=1 : ISN Greatest Common Divisor: 1
      ISR=10A : ISN Counter Rate: 266
      IP ID Sequence Generation Algorithm...
        TI=I : from TCP Seq Probes were simply incremented.
        CI=I : from Closed Ports were simply incremented.
      TS=7 : TCP Timestamp Option: 7.
    Sequence Generation 2 (SEQ)
      SP=101 : ISN Sequence Predictibily Index: 257
      GCD=1 : ISN Greatest Common Divisor: 1
      ISR=108 : ISN Counter Rate: 264
      IP ID Sequence Generation Algorithm...
        CI=I : from Closed Ports were simply incremented.
        II=I : from ICMP Probes were simply incremented.
      TS=7 : TCP Timestamp Option: 7.
    Sequence Generation 3 (SEQ)
      SP=102 : ISN Sequence Predictibily Index: 258
      GCD=1 : ISN Greatest Common Divisor: 1
      ISR=104 : ISN Counter Rate: 260
      IP ID Sequence Generation Algorithm...
        TI=I : from TCP Seq Probes were simply incremented.
        CI=I : from Closed Ports were simply incremented.
        II=I : from ICMP Probes were simply incremented.
      SS=S : IP ID is shared between TCP and ICMP packets.
      TS=7 : TCP Timestamp Option: 7.
    Sequence Generation 4 (SEQ)
      SP=106 : ISN Sequence Predictibily Index: 262
      GCD=1 : ISN Greatest Common Divisor: 1
      ISR=108 : ISN Counter Rate: 264
      IP ID Sequence Generation Algorithm...
        TI=I : from TCP Seq Probes were simply incremented.
        II=I : from ICMP Probes were simply incremented.
      SS=S : IP ID is shared between TCP and ICMP packets.
      TS=7 : TCP Timestamp Option: 7.
    TCP Options (OPS)
      O1=M200NW0NNT11
      O2=M200NW0NNT11
      O3=M200NW0NNT11
      O4=M200NW0NNT11
      O5=M200NW0NNT11
      O6=M200NNT11
    TCP Window Sizes (WIN)
      W1=4000
      W2=4000
      W3=4000
      W4=4000
      W5=4000
      W6=4000
    TCP explicit congestion notification probe (ECN)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      CC=N : Neither of these two bits is set. The target does not support ECN.
      Q= : No TCP Quirks detected
    TCP Probe Packet 1 (T1)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=O : Sequence number is something else.
      A=S+ : Acknowledgment number is the same as the sequence number in the probe plus one.
      F=AS : Acknowledgment (ACK), Synchronize (SYN).
      RD=0 : No data sent in Reset packet.
    TCP Probe Packet 2 (T2)
      R=N : Target was not responsive to this probe.
    TCP Probe Packet 3 (T3)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=O : Sequence number is something else.
      A=S+ : Acknowledgment number is the same as the sequence number in the probe plus one.
      F=AS : Acknowledgment (ACK), Synchronize (SYN).
      RD=0 : No data sent in Reset packet.
    TCP Probe Packet 4 (T4)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=A : Sequence number is the same as the acknowledgment number in the probe.
      A=Z : Acknowledgment number is zero.
      F=R : Reset (RST).
      RD=0 : No data sent in Reset packet.
    TCP Probe Packet 5 (T5)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=Z : Sequence number is zero.
      A=S+ : Acknowledgment number is the same as the sequence number in the probe plus one.
      F=AR : Acknowledgment (ACK), Reset (RST).
      RD=0 : No data sent in Reset packet.
    TCP Probe Packet 6 (T6)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=A : Sequence number is the same as the acknowledgment number in the probe.
      A=Z : Acknowledgment number is zero.
      F=R : Reset (RST).
      RD=0 : No data sent in Reset packet.
    TCP Probe Packet 7 (T7)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      Q= : No TCP Quirks detected
      S=Z : Sequence number is zero.
      A=S : Acknowledgment number is the same as the sequence number in the probe.
      F=AR : Acknowledgment (ACK), Reset (RST).
      RD=0 : No data sent in Reset packet.
    UDP Probe Packet (U1)
      R=Y : Target was responsive to this probe.
      DF=N : The "Don't Fragment" Bit was not set.
      T=40 : IP initial Time-To-Live (TTL): 64.
      IPL=38 : IP Total Length: 56
      UN=0 : Port Unreachable unused field: 0
      RIPL=G : Return Probe IP Length is good
      RID=G : Return Probe IP ID is good
      RIPCK=G : Return Checksum matches enclosing IP packet.
      RUCK=0 : Return probe UDP Checksum has a modified value of 0
      RUD=G : Return UDP data is filled with 0x43 as expected
    ICMP ECHO Packet (IE)
      R=Y : Target was responsive to this probe.
      DFI=S : Both responses echo the "Don't Fragment" Bit of the probes.
      T=40 : IP initial Time-To-Live (TTL): 64.
      CD=S : ICMP Echo Reply Response Codes match the probes.


##  brief-nmap
This is a personal nmap results filter that probably wont be useful to most people who are not me. If it is though, I'm glad it is!

### Security Advisory
This script depends on python-libnmap which is vulnerable to an XML injection (CVE-2019-1010017). There isn't a patched version as of this writing. This shouldn't be an issue if you're using this script on Nmap generated XML files that you trust. I would not advise creating a webservice based on this script and allowing anyone to upload an XML file.

You've been warned.

### Example Output
    Nmap scan summary: Nmap done at Sat Mar 21 02:27:00 2020; 256 IP addresses (4 hosts up) scanned in 25963.82 seconds
    192.168.0.4 
    8099/tcp - unknown
    9080/tcp - tcpwrapped
    13000/tcp - unknown
    56789/tcp - tcpwrapped
    56790/tcp - tcpwrapped

    192.168.0.8 
    85/tcp - unknown, but responsive!
    554/tcp - unknown, but responsive!
    8686/tcp - tcpwrapped
    37777/tcp - unknown
    
    -------------------------
    Hosts up with no open ports:
    192.168.0.7
    
    -------------------------
    Tcpwrapped ports:
    192.168.0.4:9080/tcp
    192.168.0.4:56789/tcp
    192.168.0.4:56790/tcp
    192.168.0.8:8686/tcp
    
    -------------------------
    Unknown ports:
    192.168.0.8:85/tcp
    
      GetRequest: 
        HTTP/1.1 200 OK
        CONNECTION: close
        Date: Sun, 22 Mar 2020 02:23:27 GMT
        Last-Modified: Thu, 22 Nov 2018 16:32:26 GMT
        Etag: "1542904346:5519"
        CONTENT-LENGTH: 21785
        P3P: CP=CAO PSA OUR
        X-Frame-Options: SAMEORIGIN
        CONTENT-TYPE: text/html
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> <html> <head> <title>WEB SERVICE</title> <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=6;IE=7; IE=8; IE=EmulateIE7"> <script type="text/javascript" src="jsBase/lib/jquery.js"></script> <script type="text/javascript" src="debug/testPage.js"></script> <script type="text/javascript" src="jsBase/lib/jquery.pubsub.js"></script> <script type="text/javascript" src="jsBase/widget/js/jquery.ui.core.js"></script> <script type="text/javascript" src="jsBase/widget/js/jquery.ui.widget.
      HTTPOptions: 
        HTTP/1.1 200 OK
        CONNECTION: close
        Date: Sun, 22 Mar 2020 02:23:30 GMT
        Last-Modified: Thu, 22 Nov 2018 16:32:26 GMT
        Etag: "1542904346:5519"
        CONTENT-LENGTH: 21785
        P3P: CP=CAO PSA OUR
        X-Frame-Options: SAMEORIGIN
        CONTENT-TYPE: text/html
        <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"> <html> <head> <title>WEB SERVICE</title> <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"> <meta http-equiv="X-UA-Compatible" content="IE=6;IE=7; IE=8; IE=EmulateIE7"> <script type="text/javascript" src="jsBase/lib/jquery.js"></script> <script type="text/javascript" src="debug/testPage.js"></script> <script type="text/javascript" src="jsBase/lib/jquery.pubsub.js"></script> <script type="text/javascript" src="jsBase/widget/js/jquery.ui.core.js"></script> <script type="text/javascript" src="jsBase/widget/js/jquery.ui.widget.
    
    192.168.0.8:554/tcp
    
      SIPOptions: 
        RTSP/1.0 401 Unauthorized
        CSeq: 42
        WWW-Authenticate: Digest realm="Login to 4L09D33PAZDB440", nonce="e1db55bf91821ceb8ab5f9fd65de03f9"
