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
    
        
    
    # plugin.add_argument('--hosts', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--hostports', action='store_true', help='set to return a list of affected hosts')
    # plugin.add_argument('--version', action='store_true', help='set to return a list of hosts and the version in the output')
    # plugin.add_argument('--list_plugins', action='store_true', help='set to list known plugins for standard software')
    # plugin.add_argument('--raw', action='store_true', help='set to print the raw plugin output')
    # plugin.set_defaults(func=scan_plugin)
    
