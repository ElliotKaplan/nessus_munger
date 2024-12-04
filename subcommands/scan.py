from itertools import chain
from ipaddress import ip_address
import sys

def scan_name(nessus_scan_session, clargs):
    return nessus_scan_session.scan_name()


# prints raw output from plugin
def scan_plugin_raw(nessus_scan_session, clargs):
    if (data := nessus_scan_session.scan_plugin(clargs.plugin_id)) is None:
        return ''
    outstring = ''
    for output in data:
        outstring += f'{output["plugin_output"]}\n'
        for port, portout in output['ports'].items():
            port = port.split('/')[0].strip()
            for host in portout:
                outstring += f'{host["hostname"]}:{port}\n'
    return outstring

# only print the host associated with a given plugin for the given scan
def scan_plugin_hosts(nessus_scan_session, clargs):
    if (data := nessus_scan_session.scan_plugin_hostports(clargs.plugin_id)) is None:
        return ''
    ips = sorted(set(d[0] for d in data))
    return '\n'.join(map(str, ips))

# only print the host associated with a given plugin for the given scan
def scan_plugin_hostports(nessus_scan_session, clargs):
    if (data := nessus_scan_session.scan_plugin_hostports(clargs.plugin_id)) is None:
        return ''
    ip_ports = sorted(data)
    return '\n'.join(f'{h}:{p}' for h, p in ip_ports)

# get all the plugins of a certain criticality associated with a given scan
def scan_severity(nessus_scan_session, clargs):
    params = {}
    if clargs.only_public:
        params = {
            'filter.0.quality': 'eq',
            'filter.0.filter': 'exploit_available',
            'filter.0.value': 'true',
            'filter.search_type': 'and',
            'includeHostDetailsForHostDiscovery': 'true'
        }
    resp = nessus_scan_session.get('', params=params)
    data = resp.json()
    plugins = {
        v['plugin_name']: v['plugin_id']
        for v in dat['vulnerabilities']
        if v['severity'] == clargs.severity
    }
    
        


def subcommands(subparsers):
    scan = subparsers.add_parser('scan', help='Routines for getting metadata out of a nessus scan')
    scan.add_argument('scan', type=int, help='Scan to read')

    subcommands = scan.add_subparsers()

    # metadata on the scan itself
    scans = subcommands.add_parser('name', help='Get the name of the scan')
    scans.set_defaults(func=scan_name)

    # parsing single plugin output
    plugin = subcommands.add_parser('plugin', help='choose the plugin to report')
    plugin.add_argument('plugin_id', type=int, help='plugin number')
    plugin_subcommands = plugin.add_subparsers()
    plugin_subcommands.add_parser('raw', help='Raw output from plugin').set_defaults(func=scan_plugin_raw)
    plugin_subcommands.add_parser('hosts', help='Hosts associated with plugin').set_defaults(func=scan_plugin_hosts)
    plugin_subcommands.add_parser('hostports', help='Hosts and ports associated with plugin').set_defaults(func=scan_plugin_hostports)

    # grouping by criticality
    severity = subcommands.add_parser('severity', help='print out the plugins/hosts associated with a given criticality')
    severity.set_defaults(func=scan_severity)
    severity.add_argument('severity', type=int, help="severity to find. 4: Critical, 3: High, 2: Medium, 1: Low")
    severity.add_argument('--only_public', action='store_true', help='set to only return plugins with public exploits asssocated')
    
    
        
    
    # plugin.add_argument('--hosts', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--hostports', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--version', action='store_true', help='set to return a list of hosts and the version in the output')
    # plugin.add_argument('--list_plugins', action='store_true', help='set to list known plugins for standard software')
    # plugin.add_argument('--raw', action='store_true', help='set to print the raw plugin output')
    # plugin.set_defaults(func=scan_plugin)
    
