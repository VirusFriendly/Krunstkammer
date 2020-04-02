# Wireshark-Scripts

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

This is for decoding a specific malware's c2 traffic that used the inital bytes as an XOR key for the rest of the packet data. 

See: https://www.rsreese.com/decoding-xor-payload-using-first-few-bytes-as-key/

### gits.lua

This is for decoding packet captures of PwnAdventure 3, an MMORPG game designed to be hacked.

Sample traffic is included in packet-captures/gits15.tar.gz

See: http://www.iseedeadpackets.net/2015/01/pwnadventure-3.html
