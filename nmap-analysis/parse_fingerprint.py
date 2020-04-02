"""parse_fingerprint.py

This module parses Nmap's OS and Service fingerprints into a human readable format
"""
import sys
import time

def find_fingerprints(report):
    """Scans through report text for fingerprint blocks

    Args:
        report (string): Nmap stdout output

    Returns:
        list: Each element containing fingerprint
    """
    fingerprints = list()  # Elements of Fingerprint Strings
    fp_locations = list()  # Start and stop of each fingerprint
    processing_fp = False  # Boolean: Do we have a beginning of a fingerprint with an end?

    lines = report.splitlines(keepends=True)

    for i in range(len(lines)):
        line = lines[i]

        if processing_fp:
            if line[:3] not in ["OS:", "SF:"]:
                processing_fp = False
                fp_locations[-1].append(i)
        else:
            if line[:3] in ["OS:", "SF-"]:
                processing_fp = True
                fp_locations.append([i])
    
    if processing_fp:  # In case the last line was part of the fingerprint
        processing_fp = False
        fp_locations[-1].append(len(lines))
    
    for fp in fp_locations:
        fingerprints.append(''.join(lines[fp[0]:fp[1]]))
    
    return fingerprints

def process_fingerprint(fingerprint):
    """Determines if the fingerprint is a Service or OS fingerprint and has the appropriate method process it

    Args:
        fingerprint (string): A fingerprint block, potentially produced by find_fingerprints()
    
    Returns:
        string: Type of fingerprint processes: OS or SF
        dict: contents of the parsed fingerprint
    """
    fingerprint_type = fingerprint[:3]  # Preserve the header for post trimming

    if fingerprint_type not in ["OS:", "SF-"]:
        raise Exception("Not a Nmap fingerprint")

    # Remove the Nmap formatting of the fingerprint
    fingerprint = ''.join([line[3:] for line in fingerprint.splitlines()]).encode('latin1').decode("unicode-escape")
    
    if fingerprint_type == "OS:":
        return "OS", parse_os_fingerprint(fingerprint)
    
    return "SF", parse_svc_fingerprint(fingerprint)

def parse_svc_fingerprint(fingerprint):
    """Parses a Service Fingerprint into an ordered dictionary

    Args:
        fingerprint (string): A baked Service fingerprint block
    
    Returns:
        dict: contents of the parsed fingerprint
    """
    assert(fingerprint[:4] == "Port")
    data = fingerprint[4:]
    categories = dict()

    # Parse Port Number
    categories["Port"] = data[:data.find(':')]
    data = data[data.find(':')+1:]

    # Parse Scan Line
    categories["SCAN"] = dict()

    while data[0] in "VIDTP":
        scan = data[:data.find('%')]
        data = data[len(scan)+1:]

        if scan[0] in 'VIPD':
            categories["SCAN"][scan[0]] = scan[2:]
        elif scan[:4] == "Time":
            categories["SCAN"]["Time"] = scan[5:]
        else:
            raise Exception("Unknown Scan Line Variable")
    
    categories["Strings"] = list()

    while data[:2] == 'r(':
        probe = data[2:data.find(',')]
        data = data[len(probe)+3:]
        # Response Length is not the same as the length of the response included in the fingerprint
        # response_len = int(data[:data.find(',')], 16)
        data = data[data.find(',') + 2:]
        response_len = data.find("\")%r(")

        if response_len < 0: # Is this the last probe-response?
            response_len = -3
        
        response = data[:response_len]
        data = data[response_len+3:]
        categories["Strings"].append((probe, response))
    
    return categories

def svc_fingerprint_report(categories):
    """Formats Service fingerprints in the style of fingerprint-strings.nse
    
    See: https://nmap.org/nsedoc/scripts/fingerprint-strings.html

    Args:
        categories (dict): Contents of a service fingerprint
    
    Returns:
        string: A formatted report of the service fingerprint data
    """
    report = list()
    report.append("# NMAP Service Fingerprint")
    
    if 'V' in categories["SCAN"].keys():
        report.append("Nmap Version: " + categories["SCAN"]['V'])
    
    if 'P' in categories["SCAN"].keys():
        report.append("Platform: " + categories["SCAN"]['P'])
    
    if 'D' in categories["SCAN"].keys():
        timestamp = ''

        if "Time" in categories["SCAN"].keys():
            since_epoch = int(categories["SCAN"]["Time"], 16)
            timestamp = time.strftime('%H:%M:%S', time.gmtime(since_epoch/1000.))
        
        month, day = categories["SCAN"]['D'].split('/')
        months = ['Null', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
        report.append(' '.join(["Date:", months[int(month)], day, timestamp]))
    
    if 'I' in categories["SCAN"].keys():
        # No idea yet what this is for
        report.append("I=" + categories["SCAN"]['I'])
    
    if "Port" in categories.keys():
        port = categories["Port"]
        report.append(port[:port.find('-')] + '/' + port[port.find('-')+1:].lower())
    
    # Parse Probe Responses
    probe_responses = dict()

    for probe, response in categories["Strings"]:
        if response not in probe_responses.keys():
            probe_responses[response] = list()
        
        probe_responses[response].append(probe)
    
    report.append("Probe-Responses:")

    for response in probe_responses.keys():
        report.append("|  " + ", ".join(probe_responses[response]) + ':')
        report.append("|    "+"|    ".join(response.splitlines(keepends=True)))
    
    report.append('')

    return '\n'.join(report)

def parse_os_fingerprint(fingerprint):
    """Formats OS fingerprints in a readable format

    See: https://nmap.org/book/osdetect-fingerprint-format.html

    Args:
        fingerprint (string): A baked OS fingerprint block
    
    Returns:
        string: Reports details contained in the fingerprint block
    """
    data = fingerprint
    categories = dict()
    categories["SEQ"] = list()

    # Parse OS Fingerprint
    while len(data) > 0 and data[0] in "SOWETUI":
        category = data[:data.find('(')]
        data = data[data.find('(')+1:]
        tests = data[:data.find(')')].split('%')
        data = data[data.find(')')+1:]

        testpairs = dict()

        for test in tests:
            testname, value = test.split('=')

            if testname in testpairs.keys():
                raise Exception(f"Testname: {testname} is already present in {category}")

            testpairs[testname] = value
        
        if category == "SEQ":
            categories["SEQ"].append(testpairs)
        else:
            if category in categories.keys():
                raise Exception(f"Category {category} is already present")

            categories[category] = testpairs
    
    return categories

def os_fingerprint_report(categories):
    """Formats OS fingerprints in a readable format

    See: https://nmap.org/book/osdetect-fingerprint-format.html

    Args:
        categories (dict): Contents of a service fingerprint
    
    Returns:
        string: A formatted report of the service fingerprint data
    """
    report = list()
    report.append("# NMAP OS Fingerprint")

    # Parse Scanline Results
    if "SCAN" in categories.keys():
        category = categories["SCAN"]
        report.append("Scanline (SCAN)")
        
        if 'V' in category.keys():
            report.append(f"  Nmap Version: {category['V']}")
        
        if 'P' in category.keys():
            report.append(f"  Platform: {category['P']}")
        
        if 'D' in category.keys():
            timestamp = ''

            if "TM" in category.keys():
                since_epoch = int(category["TM"], 16)
                timestamp = time.strftime('%H:%M:%S', time.gmtime(since_epoch/1000.))

            month, day = category['D'].split('/')
            months = ['Null', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
            report.append("  "+' '.join(["Date:", months[int(month)], day, timestamp]))
        
        if 'E' in category.keys():
            # No idea what this means
            report.append(f"  E={category['E']}")
        
        if "OT" in category.keys() and "CT" in category.keys():
            report.append(f"  TCP Ports: {category['OT']} open, {category['CT']} closed.")
        
        if "CU" in category.keys():
            report.append(f"  Closed UDP Ports: {category['CU']}.")
        
        if "PV" in category.keys():
            private_flag = "private"

            if category["PV"] == 'N':
                private_flag = "public"
            
            report.append(f"  Target was on a {private_flag} network.")

        if "DS" in category.keys():
            ttl = ''

            if "DC" in category.keys():
                if category["DC"] == 'I':
                    ttl = ", determined by ICMP response TTL"
                elif category["DC"] == 'T':
                    ttl = ", determined by traceroute"
            
            if category["DS"] == "0":
                report.append("  Target was the localhost.")
            elif category["DS"] == "1":
                mac = ''

                if 'M' in category.keys():
                    mac = f", and had a MAC prefix of {category['M']}"

                report.append(f"  Target was on the local network{mac}.")
            else:
                report.append(f"  Target was {category['DS']} hops away{ttl}.")
        
        if 'G' in category.keys():
            good_flag = ''

            if category['G'] == 'N':
                good_flag = 'un'
            
            report.append(f"  This OS Fingerprint is {good_flag}acceptible for submission.")
    
    # Parse Sequence Generation Results
    for generation in range(len(categories["SEQ"])):
        report.append(f"Sequence Generation {generation+1} (SEQ)")
        seq = categories["SEQ"][generation]

        if "SP" in seq.keys():
            report.append(f"  SP={seq['SP']} : ISN Sequence Predictibily Index: {int(seq['SP'],16)}")
        
        if "GCD" in seq.keys():
            report.append(f"  GCD={seq['GCD']} : ISN Greatest Common Divisor: {int(seq['GCD'],16)}")
        
        if "ISR" in seq.keys():
            report.append(f"  ISR={seq['ISR']} : ISN Counter Rate: {int(seq['ISR'],16)}")
        
        if "TI" in seq.keys() or "CI" in seq.keys() or "II" in seq.keys():
            report.append("  IP ID Sequence Generation Algorithm...")

            ipid_values = dict()
            ipid_values['Z'] = "were all zero"
            ipid_values["RD"] = "were random"
            ipid_values["RDI"] = "were randomly positive increased"
            ipid_values["BI"] = "were broken incremented (often caused by host byte order)"
            ipid_values["I"] = "were simply incremented"

            ipid_tests = dict()
            ipid_tests["TI"] = "TCP Seq Probes"
            ipid_tests["CI"] = "Closed Ports"
            ipid_tests["II"] = "ICMP Probes"

            for ipid_test in ipid_tests.keys():
                if ipid_test not in seq.keys():
                    continue

                if seq[ipid_test] in ipid_values.keys():
                    report.append(f"    {ipid_test}={seq[ipid_test]} : from {ipid_tests[ipid_test]} {ipid_values[seq[ipid_test]]}.")
                else:
                    report.append(f"    {ipid_test}={seq[ipid_test]} : from {ipid_tests[ipid_test]} was incremented by {int(seq[ipid_test],16)}.")
        
        if "SS" in seq.keys():
            flag = ""

            if seq["SS"] == "O":
                flag = "not "

            report.append(f"  SS={seq['SS']} : IP ID is {flag}shared between TCP and ICMP packets.")

        if "TS" in seq.keys():
            seqts = {
                'U': "TCP Timestamp Option is Unsupported",
                '0': "One or more TCP Responces has a null Timestamp value"
            }

            if seq["TS"] in seqts.keys():
                report.append(f"  TS={seq['TS']} : {seqts[seq['TS']]}.")
            else:
                report.append(f"  TS={seq['TS']} : TCP Timestamp Option: {seq['TS']}.")
    
    # Parse TCP Options Results
    if "OPS" in categories.keys():
        category = categories["OPS"]
        report.append("TCP Options (OPS)")

        for i in range(1, 7):
            report.append(f"  O{i}={category['O'+str(i)]}")
    
    # Parse TCP Window Sizes
    if "WIN" in categories.keys():
        category = categories["WIN"]
        report.append("TCP Window Sizes (WIN)")

        for i in range(1, 7):
            report.append(f"  W{i}={category['W'+str(i)]}")
    
    test_categories = {
        "ECN": "TCP explicit congestion notification probe",
        "T1": "TCP Probe Packet 1",
        "T2": "TCP Probe Packet 2",
        "T3": "TCP Probe Packet 3",
        "T4": "TCP Probe Packet 4",
        "T5": "TCP Probe Packet 5",
        "T6": "TCP Probe Packet 6",
        "T7": "TCP Probe Packet 7",
        "U1": "UDP Probe Packet",
        "IE": "ICMP ECHO Packet"
    }

    # Parse TCP explicit congestion notification
    for category in test_categories.keys():
        if category not in categories.keys():
            pass

        report.append(f"{test_categories[category]} ({category})")
        report.append(report_test_results(categories[category]))
    
    
    for category in categories.keys():
        if category not in ["SCAN", "SEQ", "OPS", "WIN", "ECN", "T1", "T2", "T3", "T4", "T5", "T6", "T7", "U1", "IE"]:
            raise ValueError
    
    report.append('')

    return '\n'.join(report)

def report_test_results(tests):
    """Reports results from the OS Scan Probes

    These test results are common across multiple categories

    See: https://nmap.org/book/osdetect-fingerprint-format.html

    Args:
        tests (dictionary): A collection of tests and test results
    
    Returns:
        string: Reports details contained in the fingerprint block
    """
    report = list()

    if 'R' in tests.keys():
        flag = ''

        if tests['R'] == 'N':
            flag = 'not '
        
        report.append(f"  R={tests['R']} : Target was {flag}responsive to this probe.")
    
    if "DF" in tests.keys():
        flag = ''

        if tests["DF"] == 'N':
            flag = 'not '

        report.append(f"  DF={tests['DF']} : The \"Don't Fragment\" Bit was {flag}set.")
    
    if "DFI" in tests.keys():
        dfi = {
            'N': "Neither ICMP response had the \"Don't Fragment\" Bit set",
            'S': "Both responses echo the \"Don't Fragment\" Bit of the probes",
            'Y': "Both of the response \"Don't Fragment\" Bits were set",
            'O': "Both responses have the \"Don't Fragment\" Bits toggled"
        }

        if tests["DFI"] in dfi.keys():
            report.append(f"  DFI={tests['DFI']} : {dfi[tests['DFI']]}.")
        else:
            raise ValueError
    
    if 'T' in tests.keys():
        report.append(f"  T={tests['T']} : IP initial Time-To-Live (TTL): {int(tests['T'],16)}.")
    
    if "TG" in tests.keys():
        report.append(f"  TG={tests['TG']} : IP initial Time-To-Live (TTL) Guess: {int(tests['TG'],16)}.")
    
    if "CC" in tests.keys():
        cc = {
            'Y': "Only the ECE bit is set (not CWR). This host supports ECN",
            'N': "Neither of these two bits is set. The target does not support ECN",
            'S': "Both bits are set. The target does not support ECN, but it echoes back what it thinks is a reserved bit",
            'O': "The CWR bit is set and not the ECE bit. This is unexpected"
        }

        if tests["CC"] in cc.keys():
            report.append(f"  CC={tests['CC']} : {cc[tests['CC']]}.")
        else:
            raise ValueError
    
    if 'Q' in tests.keys():
        quirk = ''

        if tests['Q'] == '':
            quirk = "No TCP Quirks detected"
        else:
            quirks = list()

            if 'R' in tests['Q']:
                quirks.append("Reserved Field is non-zero")
            
            if 'U' in tests['Q']:
                quirks.append("Urgent Pointer Field is non-zero")

            quirk = "Quirks:"+", ".join(quirks)
        
        report.append(f"  Q={tests['Q']} : {quirk}")
    
    if 'S' in tests.keys():
        seqnum = {
            'Z': "Sequence number is zero",
            'A': "Sequence number is the same as the acknowledgment number in the probe",
            'A+': "Sequence number is the same as the acknowledgment number in the probe plus one",
            'O': "Sequence number is something else"
        }

        if tests['S'] in seqnum.keys():
            report.append(f"  S={tests['S']} : {seqnum[tests['S']]}.")
        else:
            raise ValueError
    
    if 'A' in tests.keys():
        acks = {
            'Z': "Acknowledgment number is zero",
            'S': "Acknowledgment number is the same as the sequence number in the probe",
            'S+': "Acknowledgment number is the same as the sequence number in the probe plus one",
            'O': "Acknowledgment number is something else"
        }

        if tests['A'] in acks.keys():
            report.append(f"  A={tests['A']} : {acks[tests['A']]}.")
        else:
            raise ValueError
    
    if 'F' in tests.keys():
        f_label = {
            'E': "ECN Echo (ECE)",
            'U': "Urgent Data (URG)",
            'A': "Acknowledgment (ACK)",
            'P': "Push (PSH)",
            'R': "Reset (RST)",
            'S': "Synchronize (SYN)",
            'F': "Final (FIN)"
        }

        if len(tests['F']) > 0:
            flags = list()

            for flag in tests['F']:
                if flag in f_label:
                    flags.append(f_label[flag])
                else:
                    raise ValueError
            
            report.append(f"  F={tests['F']} : {', '.join(flags)}.")
    
    if "RD" in tests.keys():
        if tests["RD"] == '0':
            report.append(f"  RD={tests['RD']} : No data sent in Reset packet.")
        else:
            report.append(f"  RD={tests['RD']} : Data sent inside Reset packet with a crc32 of: {tests['RD']}.")
    
    if "IPL" in tests.keys():
        report.append(f"  IPL={tests['IPL']} : IP Total Length: {int(tests['IPL'],16)}")
    
    if "UN" in tests.keys():
        report.append(f"  UN={tests['UN']} : Port Unreachable unused field: {tests['UN']}")
    
    if "RIPL" in tests.keys():
        if tests["RIPL"] == 'G':
            report.append("  RIPL=G : Return Probe IP Length is good")
        else:
            report.append(f"  RIPLE={tests['RIPL']} : Return Probe IP doesn't match the Orginal IP Header. Expect 328 bytes, received {int(tests['RIPL'],16)}")
    
    if "RID" in tests.keys():
        if tests["RID"] == "G":
            report.append("  RID=G : Return Probe IP ID is good")
        elif tests["RID"] == "4210":
            report.append("  RID=4210 : Return Probe flipped the byte order of the IP ID. This is typical of HP and Xerox Printers.")
        else:
            report.append(f"  RID={tests['RID']} : Return Probe IP ID was modified to be 0x{tests['RID']}.")
    
    if "RIPCK" in tests.keys():
        ripcks = {
            'G': '  RIPCK=G : Return Checksum matches enclosing IP packet.',
            'Z': '  RIPCK=Z : Return Checksum is Zero',
            'I': '  RIPCK=I : Return Checksum is Invalid'
        }

        if tests["RIPCK"] in ripcks.keys():
            report.append(ripcks[tests["RIPCK"]])
        else:
            raise ValueError
    
    if "RUCK" in tests.keys():
        if tests["RUCK"] == 'G':
            report.append("  RUCK=G : Return probe UDP Checksum is good.")
        else:
            report.append(f"  RUCK={tests['RUCK']} : Return probe UDP Checksum has a modified value of {tests['RUCK']}")
    
    if "RUD" in tests.keys():
        ruds = {
            'G': "  RUD=G : Return UDP data is filled with 0x43 as expected",
            'I': "  RUD=I : Return UDP data was modified"
        }

        if tests["RUD"] in ruds.keys():
            report.append(ruds[tests["RUD"]])
        else:
            raise ValueError
    
    if "CD" in tests.keys():
        cd_labels = {
            'Z': "  CD=Z : ICMP Echo Reply Response Codes were zero. As expected.",
            'S': "  CD=S : ICMP Echo Reply Response Codes match the probes.",
            'O': "  CD=O : ICMP Echo Reply Response Codes don't match the probes, but atleast one is zero."
        }

        if tests["CD"] in cd_labels.keys():
            report.append(cd_labels[tests["CD"]])
        else:
            report.append(f"  CD={tests['CD']} : ICMP Echo Reply Response Codes are expected with values {tests['CD']}.")
    
    return '\n'.join(report)

def strip_fingerprint(fingerprint):
    """ If you just want to remove the Nmap format. Great for Debugging!

    Args:
        fingerprint (string): A raw OS fingerprint block
    
    Returns:
        string: a baked OS fingerprint block
    """
    return ''.join([line[3:] for line in fingerprint.splitlines()]).encode('latin1').decode("unicode-escape")


if __name__ == '__main__':
    for filename in sys.argv[1:]:
        f = open(filename)
        fingerprints = find_fingerprints(f.read())

        for fingerprint in fingerprints:
            fp_type, data = process_fingerprint(fingerprint)

            if fp_type == "OS":
                print(os_fingerprint_report(data))
            elif fp_type == "SF":
                print(svc_fingerprint_report(data))
            else:
                raise ValueError

