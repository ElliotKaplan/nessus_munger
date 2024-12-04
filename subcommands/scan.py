import sys

def scan_name(nessus_scan_session, clargs):
    return nessus_scan_session.scan_name()

def subcommands(subparsers):
    scan = subparsers.add_parser('scan', help='Routines for getting metadata out of a nessus scan')
    scan.add_argument('scan', type=int, help='Scan to read')

    subcommands = scan.add_subparsers()
    scans = subcommands.add_parser('name', help='Get the name of the scan')
    scans.set_defaults(func=scan_name)
