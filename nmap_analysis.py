"""My personal Nmap report parser for information I find useful and excludes information that I'm not interested in.
"""
import sys
from libnmap.parser import NmapParser

def brief_nmap(nmap_report):
    """Formats Nmap's report for quick overview

    Condenses the Nmap report to bare essentials

    Calls special attention to unknown ports, tcpwrapped ports, and hosts with no open ports.

    Args:
        nmap_report ():

    Returns:
        string: Formated report output
    """
    report = list()
    empty_hosts = list()
    wrapped_ports = list()
    unknown_ports = list()
    divider = "-------------------------"

    report.append(f"Nmap scan summary: {format(nmap_report.summary)}")

    for scanned_hosts in nmap_report.hosts:
        if len(scanned_hosts.get_open_ports()) == 0:
            empty_hosts.append(scanned_hosts.address)
            continue

        host_address = scanned_hosts.address+' '+scanned_hosts.mac

        if len(scanned_hosts.os_match_probabilities()) > 0:
            host_address = host_address + ' '+scanned_hosts.os_match_probabilities()[0].name
        
        report.append(host_address)

        if len(scanned_hosts.hostnames):
            report.append(scanned_hosts.hostnames)

        for ports in scanned_hosts.get_open_ports():
            service=scanned_hosts.get_service(ports[0], ports[1])
            scripts = [script["id"] for script in service.scripts_results]

            port = f"{str(ports[0])}/{ports[1]}"

            if str(service).find("tcpwrapped") > 0:
                report.append(f"{port} - tcpwrapped")
                wrapped_ports.append(scanned_hosts.address+':'+port)
            elif len(service.banner) == 0 or str(service).find("unknown") != -1:
                output = f"{port} - unknown"

                if "fingerprint-strings" in scripts:  # See if the port responded to any probes
                    output = output + ", but responsive!"
                    unknown_port=scanned_hosts.address+':'+port
                    
                    for script in service.scripts_results:
                        if script["id"] == "fingerprint-strings":
                            unknown_ports.append((unknown_port, script["output"]))
                
                report.append(output)
            elif "fingerprint-strings" in scripts:
                report.append(f"{port} - Guess: ({service.banner})")
                unknown_port=scanned_hosts.address+':'+port
                    
                for script in service.scripts_results:
                    if script["id"] == "fingerprint-strings":
                        unknown_ports.append((unknown_port, script["output"]))
            else:
                report.append(f"{port} - {service.banner}")
                data=script_filter(service.scripts_results)

                if data != '':
                    report.append(data)
        
        report.append('')

    if len(empty_hosts) > 0:
        report.append(divider)
        report.append("Hosts up with no open ports:")

        for host in empty_hosts:
            report.append(host)

        report.append('')
    
    if len(wrapped_ports) > 0:
        report.append(divider)
        report.append("Tcpwrapped ports:")

        for wrapped_port in wrapped_ports:
            report.append(wrapped_port)
        
        report.append('')

    if unknown_ports != {}:
        report.append(divider)
        report.append("Unknown ports:")

        for unknown_port, unknown_service in unknown_ports:
            report.append('\n'.join([unknown_port, unknown_service, '']))
    
    return '\n'.join(report)

def script_filter(script_results):
    report = list()

    for script_result in script_results:
        if script_result["id"] == "http-auth":
            output = script_result['output'].split('\n')[2]
            report.append(f"-- http-auth: {output}")
        elif script_result["id"] == "http-methods":
            if "No Allow or Public header in OPTIONS response" not in script_result["output"]:
                output = script_result["output"].split('\n')[0]
                report.append(f"-- http-methods: {output}")
        elif script_result["id"] == "http-server-header":
            report.append(f"-- http-server-header: {script_result['output']}")
        elif script_result["id"] == "http-title":
            filters = [
                "301 Moved Permanently",
                "302 Found",
                "401 Authorization Required",
                "403 Forbidden",
                "404 Not Found",
                "500 - Internal server error.",
                "Bad Request",
                "Did not follow redirect to",
                "Redirecting...",
                "Service Unavailable",
                "Site doesn't have a title"
            ]
        
            if script_result["elements"]["title"] not in filters:
                report.append(f"-- http-title: {script_result['elements']['title']}")
        elif script_result["id"] == "sslv2":
            if "server supports SSLv2 protocol, but no SSLv2 cyphers" not in script_result['output']:
                output = script_result["output"].split('\n')[0]
                report.append(f"-- sslv2: {output}")
        elif script_result["id"] == "ssl-cert":
            output = f"-- ssl-cert: {script_result['elements']['subject']['commonName']},"
            output = output + f" expires: {script_result['elements']['validity']['notAfter']}"
            output = output + f" issued by: {script_result['elements']['issuer']['commonName']}"
            report.append(output)
        else:
            report.append(f"-- {script_result['id']}: ")

            for result in script_result["output"].split('\n'):
                report.append("--- "+result)

    return '\n'.join(report)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage: '+sys.argv[0]+' <nmapreport.xml>')
    else:
        print(brief_nmap(NmapParser.parse_fromfile(sys.argv[1])))

