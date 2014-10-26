from libnmap.parser import NmapParser

def result_filter(script_result):
    report = '-- '+script_result['id']+': '+'\n--- '.join(script_result['output'].split("\n"))

    if script_result['elements'] != {}:
        print 'ELEMENTS ISN\'T NULL'
        print script_result

    if script_result['id'] == 'http-auth':
        report = '-- '+script_result['id']+': '+script_result['output'].split("\n")[2]

    if script_result['id'] == 'http-methods':
        if 'No Allow or Public header in OPTIONS response' in script_result['output']:
            report=''
        else:
            report = '-- '+script_result['id']+': '+script_result['output'].split("\n")[0]

    if script_result['id'] == 'http-title':
        filters = [
            '301 Moved Permanently',
            '302 Found',
            '401 Authorization Required',
            '403 Forbidden',
            '404 Not Found',
            'Did not follow redirect to',
            'Redirecting...',
            'Site doesn\'t have a title'
        ]

        for filter in filters:
            if filter in script_result['output']:
                report=''
    if script_result['id'] == 'sslv2':
        if 'server supports SSLv2 protocol, but no SSLv2 cyphers' in script_result['output']:
            report=''


    if script_result['id'] == 'ssl-cert':
        for field in script_result['output'].split('/'):
            if 'Subject: ' in field:
                report = '-- '+script_result['id']+': '+field.split('=')[1]
        

    return report

nmap_report = NmapParser.parse_fromfile('test.xml')
print "Nmap scan summary: {0}".format(nmap_report.summary)


empty_hosts=[]
unknown_ports = {}

for scanned_hosts in nmap_report.hosts:
    if len(scanned_hosts.get_open_ports()) > 0:
        if len(scanned_hosts.os_match_probabilities()) > 0:
            print scanned_hosts.address+' '+scanned_hosts.mac+' '+scanned_hosts.os_match_probabilities()[0].name
        else:
            print scanned_hosts.address+' '+scanned_hosts.mac

        if len(scanned_hosts.hostnames):
            print scanned_hosts.hostnames

        for ports in scanned_hosts.get_open_ports():
            print str(ports[0])+'/'+ports[1]
            service=scanned_hosts.get_service(ports[0], ports[1])

            if service.banner != '':
                print '- '+service.banner

                for scripts in service.scripts_results:
                    data=result_filter(scripts)

                    if data != '':
                        print data

            else:
                print '- unknown'

                if service.servicefp != '':
                    key=scanned_hosts.address+':'+str(ports[0])+'/'+ports[1]
                    unknown_ports[key]='\n'.join(service.servicefp.split("%r")[1:])

        print ''
    else:
        empty_hosts.append(scanned_hosts.address)

if (empty_hosts) > 0:
    print 'Hosts up with no open ports:'

    for host in empty_hosts:
        print host

    print ''


if unknown_ports != {}:
    print 'Unknown ports:'

    for key in unknown_ports.keys():
        print key
        print unknown_ports[key]
        print ''

