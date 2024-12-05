import sys

def folder_scans(nessus_folder_session, clargs):
    folder = clargs.folder

    scans = nessus_folder_session.scan_ids
    if clargs.descending:
        scans = scans[::-1]
    # only need scan numbers if this is being piped elsewhere
    if not sys.stdout.isatty():
        return ' '.join(
            str(s[0]) for s in scans
        )
    # print the scan name if this is a tty out
    return '\n'.join(
        f'{s[0]}\t{s[1]}' for s in scans
    )

def folder_plugin_hosts(nessus_folder_session, clargs):
    if (data := nessus_folder_session.folder_plugin_hostports(clargs.plugin_id)) is None:
        return ''
    # set eliminates duplicates
    ips = sorted(set(d[0] for d in data))
    return '\n'.join(map(str, ips))
    
# only print the host associated with a given plugin for the given scan
def folder_plugin_hostports(nessus_folder_session, clargs):
    if (data := nessus_folder_session.folder_plugin_hostports(clargs.plugin_id)) is None:
        return ''
    ip_ports = sorted(data)
    return '\n'.join(f'{h}:{p}' for h, p in ip_ports)

def subcommands(subparsers):
    folder = subparsers.add_parser('folder', help='Routines for getting metadata out of a nessus folder')
    folder.add_argument('folder', type=int, help='Folder to read')

    subcommands = folder.add_subparsers()
    scans = subcommands.add_parser('scans', help='List the scans in the folder')
    scans.add_argument('-d', '--descending', action='store_true',
                       help='set to reverse order of list')
    scans.set_defaults(func=folder_scans)

    plugin = subcommands.add_parser('plugin', help='choose the plugin to report')
    plugin.add_argument('plugin_id', type=int, help='plugin number')
    plugin_subcommands = plugin.add_subparsers()
    plugin_subcommands.add_parser('hosts', help='Hosts associated with plugin').set_defaults(func=folder_plugin_hosts)
    plugin_subcommands.add_parser('hostports', help='Hosts and ports associated with plugin').set_defaults(func=folder_plugin_hostports)

    
    
    
    
