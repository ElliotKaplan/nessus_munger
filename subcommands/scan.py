from itertools import chain
from ipaddress import ip_address
import sys

def scan_name(nessus_scan_session, clargs):
    return nessus_scan_session.scan_name()


# root for reading plugin data
def scan_plugin(nessus_scan_session, clargs):
    resp = nessus_scan_session.get(f'/plugins/{clargs.plugin_id}')
    data = resp.json()
    return data['outputs']

# prints raw output from plugin
def scan_plugin_raw(nessus_scan_session, clargs):
    if (data := scan_plugin(nessus_scan_session, clargs)) is None:
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
    if (data := scan_plugin(nessus_scan_session, clargs)) is None:
        return ''
    # set {} removes duplicates, casting to an ip_address object sorts
    # properly, and chaining covers all ports
    ips = sorted({*chain(
                (
                    h['hostname']
                    for d in data
                    for p in d['ports'].values()
                    for h in p
                )
            )
        }, key=ip_address
    )
    return '\n'.join(ips)

# only print the host associated with a given plugin for the given scan
def scan_plugin_hostports(nessus_scan_session, clargs):
    if (data := scan_plugin(nessus_scan_session, clargs)) is None:
        return ''
    # set {} removes duplicates, casting to an ip_address object sorts
    # properly, and chaining covers all ports
    ip_ports = sorted(
        chain(
            (ip_address(h["hostname"]), int(p.split(" / ")[0]))
            for d in data
            for p, hs in d['ports'].items()
            for h in hs
        )
    )
    return '\n'.join(f'{h}:{p}' for h, p in ip_ports)


def subcommands(subparsers):
    scan = subparsers.add_parser('scan', help='Routines for getting metadata out of a nessus scan')
    scan.add_argument('scan', type=int, help='Scan to read')

    subcommands = scan.add_subparsers()

    scans = subcommands.add_parser('name', help='Get the name of the scan')
    scans.set_defaults(func=scan_name)

    plugin = subcommands.add_parser('plugin', help='choose the plugin to report')
    plugin.add_argument('plugin_id', type=int, help='plugin number')
    plugin_subcommands = plugin.add_subparsers()
    plugin_subcommands.add_parser('raw', help='Raw output from plugin').set_defaults(func=scan_plugin_raw)
    plugin_subcommands.add_parser('hosts', help='Hosts associated with plugin').set_defaults(func=scan_plugin_hosts)
    plugin_subcommands.add_parser('hostports', help='Hosts and ports associated with plugin').set_defaults(func=scan_plugin_hostports)

    
    
        
    
    # plugin.add_argument('--hosts', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--hostports', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--version', action='store_true', help='set to return a list of hosts and the version in the output')
    # plugin.add_argument('--list_plugins', action='store_true', help='set to list known plugins for standard software')
    # plugin.add_argument('--raw', action='store_true', help='set to print the raw plugin output')
    # plugin.set_defaults(func=scan_plugin)
    
