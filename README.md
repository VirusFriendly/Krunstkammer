![Krunstkammer's Logo](https://github.com/VirusFriendly/Krunstkammer/blob/master/assets/kunstkammer-logo.png)

### A protocol researcher's collection of tools, dissectors, and specimins.

I search for unknown or unusual protocols, whether they are malware C2, proprietary, or just some new service that hasn't received enough attention. **Krunstkammer** is my bag of wonders and tools of my trade.

Each directory has a README to describe their purpose in more detail.

## Summury/Workflow

** Nmap Analysis ** are the tools I use to find and isolate unknown services, which are stored in ** Nmap Signatures **. Then I collect ** packet captures ** for protocols I have or can build clients for and reverse engineer the protocol by building ** protocol dissectors **. Lastly, if the protocol has interesting details that can be easily probed, I make a special ** nse-script ** for it.
