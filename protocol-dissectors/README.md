# Wireshark-Scripts

This is part of a collection of *-scripts repositories. Each of which are modules for a larger framework. In this case Wireshark.

Website for this project: http://www.erisresearch.org/#Wireshark%20Modules

## Installation

You need to first have Wireshark installed and make sure it supports LUA (See: https://wiki.wireshark.org/Lua#Getting_Started). Then place the scripts in the following locations.

Unix:

* /usr/share/wireshark/plugins
* /usr/local/share/wireshark/plugins
* $HOME/.wireshark/plugins

Windows:

* %WIRESHARK%\plugins\<version>
* %APPDATA%\Wireshark\plugins

## Script Specific Information

### xor64.lua

This is for decoding a specific malware's c2 traffic that used the inital bytes as an XOR key for the rest of the packet data. For more information see: https://www.rsreese.com/decoding-xor-payload-using-first-few-bytes-as-key/

### gits.lua

This is for decoding packet captures of PwnAdventure 3, an MMORPG game designed to be hacked. My strategy was to reverse engineer the protocol and write a proxy allowing for crazy features. Sadly this strategy was not a quick as other strategies that involved reversing the client, and I didn't have time to write the proxy. However, reverse engineering protocols is always fun.

Sample traffic is included in samples/gits15.tar.gz

Since this challenge, I have learned how to better craft my scripts and will update the script, and reverse engineer more of the protocol.

http://www.iseedeadpackets.net/2015/01/pwnadventure-3.html