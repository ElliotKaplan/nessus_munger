import json

def launch_scan(nessus_scan_session, clargs):
    data = nessus_scan_session.scan_launch()
    return json.dumps(data)

def subparsers(subparsers):
    launch = subparsers.add_parser('launch', help='Routines to launch one or more scans from the command line')

    subcommands = launch.add_subparsers()

    scan = subcommands.add_parser('scan', help='Launch a single scan')
    scan.add_argument('scan', type=int, help='Scan to launch')
    scan.set_defaults(func=launch_scan)
