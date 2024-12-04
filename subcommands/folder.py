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

def subcommands(subparsers):
    folder = subparsers.add_parser('folder', help='Routines for getting metadata out of a nessus folder')
    folder.add_argument('folder', type=int, help='Folder to read')

    subcommands = folder.add_subparsers()
    scans = subcommands.add_parser('scans', help='List the scans in the folder')
    scans.add_argument('-d', '--descending', action='store_true',
                       help='set to reverse order of list')
    scans.set_defaults(func=folder_scans)

    
    
    
