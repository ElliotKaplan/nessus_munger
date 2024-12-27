from itertools import chain
from ipaddress import ip_address
from collections import Counter
import sys

from utilities import string_processing

def scan_name(nessus_scan_session, clargs):
    return nessus_scan_session.scan_name()

# wrapper for routines that spit out dictionaries of plugins
def plugin_summary(func):
    def wrapped(nessus_scan_session, clargs):
        plugins = func(nessus_scan_session, clargs)
        outstring = ''    
        if sys.stdout.isatty():
            for pluginid, pluginname in plugins.items():
                ips = sorted(set(str(d[0]) for d in nessus_scan_session.scan_plugin_hostports(pluginid)))
                head = f'{pluginid:>10d}: {pluginname} ({len(ips)} Host{"s" if len(ips)!=1 else ""})'
                outstring += f'{head}\n{"="*len(head)}\n'
                outstring += '\n'.join(map(str, ips))
                outstring += '\n\n'
        else:
            # assume that this is going to be passed to awk for more
            # processing. first column is plugin, subsequent columns are
            # hosts
            for pluginid, pluginname in plugins.items():
                ips = sorted(set(str(d[0]) for d in nessus_scan_session.scan_plugin_hostports(pluginid)))
                outstring += f'{pluginid} {" ".join(map(str, ips))}\n'

        return outstring
    return wrapped

# get the scan plugin description
def scan_plugin_description(nessus_scan_session, clargs):
    resp = nessus_scan_session.get(f'/plugins/{clargs.plugin_id}')
    data = resp.json()
    return data['info']['plugindescription']['pluginattributes']['description']

def scan_plugin_cves(nessus_scan_session, clargs):
    resp = nessus_scan_session.get(f'/plugins/{clargs.plugin_id}')
    data = resp.json()
    refs = data['info']['plugindescription']['pluginattributes']['ref_information']['ref']
    out = ''
    for ref in refs:
        if ref['name'] == 'cve':
            out += '\n'.join(ref['values']['value'])
    return out

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
    # set eliminates duplicates
    ips = sorted(set(d[0] for d in data))
    return '\n'.join(map(str, ips))

# only print the host associated with a given plugin for the given scan
def scan_plugin_hostports(nessus_scan_session, clargs):
    if (data := nessus_scan_session.scan_plugin_hostports(clargs.plugin_id)) is None:
        return ''
    ip_ports = sorted(data)
    return '\n'.join(f'{h}:{p}' for h, p in ip_ports)

# get all the plugins of a certain criticality associated with a given scan
@plugin_summary
def scan_severity(nessus_scan_session, clargs):
    filter_params = {
        'filter.search_type': 'and',
        'filter.0.quality': 'eq',
        'filter.0.filter': 'severity',
        'filter.0.value': clargs.severity,
        'filter.1.quality': 'nmatch',
        'filter.1.filter': 'plugin_name',
        'filter.1.value': 'TLS',
        'filter.2.quality': 'nmatch',
        'filter.2.filter': 'plugin_name',
        'filter.2.value': 'SSL',
    }

    if clargs.only_public:
        filterparams.update(
            {
                'filter.3.quality': 'eq',
                'filter.3.filter': 'exploit_available',
                'filter.3.value': 'true',
            }
        )
        
    return nessus_scan_session.scan_vulnerabilities(filter_params)


# only return tsl  or ssl findings
@plugin_summary
def scan_tls(nessus_scan_session, clargs):
    # gather tls findings of minimum severity
    # minus 1 is because there is no ge, only gt
    filter_params = {
        'filter.search_type': 'and',
        'filter.0.quality': 'match',
        'filter.0.filter': 'plugin_name',
        'filter.0.value': 'TLS',
        'filter.1.quality': 'gt',
        'filter.1.filter': 'severity',
        'filter.1.value': clargs.min_severity-1,
    }
    plugins = nessus_scan_session.scan_vulnerabilities(filter_params)
    # include ssl findings of minimum severity
    filter_params = {
        'filter.search_type': 'and',
        'filter.0.quality': 'match',
        'filter.0.filter': 'plugin_name',
        'filter.0.value': 'SSL',
        'filter.1.quality': 'gt',
        'filter.1.filter': 'severity',
        'filter.1.value': clargs.min_severity-1,
    }
    plugins.update(nessus_scan_session.scan_vulnerabilities(filter_params))

    return plugins

# only return unsupported software findings
@plugin_summary
def scan_unsupported(nessus_scan_session, clargs):
    filter_params = {
        'filter.0.quality': 'match',
        'filter.0.filter': 'plugin_name',
        'filter.0.value': 'unsupported',
        'filter.search_type': 'and'
    }
    return nessus_scan_session.scan_vulnerabilities(filter_params)

@plugin_summary
def scan_cpe(nessus_scan_session, clargs):
    filter_params = {
        'filter.0.quality': 'match',
        'filter.0.filter': 'cpe',
        'filter.0.value': clargs.cpe_tag,
        'filter.search_type': 'and',
        'filter.1.quality': 'gt',
        'filter.1.filter': 'severity',
        'filter.1.value': clargs.min_severity-1,
    }
    return nessus_scan_session.scan_vulnerabilities(filter_params)


# list the unique values of cpe
def scan_cpe_list(nessus_scan_session, clargs):
    resp = nessus_scan_session.get('')
    data = resp.json()
    cpes = Counter(v['cpe'] for v in data['vulnerabilities'])
    nocpe = cpes.pop(None)
    padwidth = max(map(len, cpes.keys()))
    out = '\n'.join(
        f'{key:<{padwidth}s} {cpes[key]}' for key in sorted(cpes))
    out += f'\n{"None":<{padwidth}s} {cpes[None]}'
    return out

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
    plugin_subcommands.add_parser('description', help='Read the plugin description').set_defaults(func=scan_plugin_description)
    plugin_subcommands.add_parser('cves', help='Read the plugin cves').set_defaults(func=scan_plugin_cves)

    # grouping by criticality
    severity = subcommands.add_parser('severity', help='print out the plugins/hosts associated with a given criticality')
    severity.set_defaults(func=scan_severity)
    severity.add_argument('severity', type=int, help="severity to find. 4: Critical, 3: High, 2: Medium, 1: Low\nThis specifically ignores SSL/TLS related findings and unsupported software")
    severity.add_argument('--only_public', action='store_true', help='set to only return plugins with public exploits asssocated')

    # tls/ssl related vulns
    tlsssl = subcommands.add_parser('tls', help='print out the plugins/hosts associated with TLS/SSL issues')
    tlsssl.add_argument('--min_severity', type=int, default=3, help="mimimum severity to list")
    tlsssl.set_defaults(func=scan_tls)

    # Unsupported software
    subcommands.add_parser('unsupported', help='print out the plugins/hosts associated with unsupported software').set_defaults(func=scan_unsupported)

    cpe = subcommands.add_parser('cpe', help='only return plugins associated with a given cpe')
    cpe.add_argument('cpe_tag', type=str, help='cpe label')
    cpe.add_argument('--min_severity', type=int, default=3, help="mimimum severity to list")
    cpe.set_defaults(func=scan_cpe)
    cpe_subcommands = cpe.add_subparsers()
    cpe_subcommands.add_parser('list', help='list avaiable cpes for the scan (requires cpe input)').set_defaults(func=scan_cpe_list)
    
    
    
    
        
    
    # plugin.add_argument('--hosts', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--hostports', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--version', action='store_true', help='set to return a list of hosts and the version in the output')
    # plugin.add_argument('--list_plugins', action='store_true', help='set to list known plugins for standard software')
    # plugin.add_argument('--raw', action='store_true', help='set to print the raw plugin output')
    # plugin.set_defaults(func=scan_plugin)
    
