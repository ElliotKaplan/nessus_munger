import sys

def folder_scans(nessus_session, clargs):
    folder = clargs.folder
    descending = clargs.descending
    resp = nessus_session.get('scans', params={'folder_id': folder})

    scans = resp.json()['scans']

    # only need scan numbers if this is being piped elsewhere
    if not sys.stdout.isatty():
        return ' '.join(
            map(
                str,
                sorted(
                    (s['id'] for s in scans),
                    reverse=descending
                )
            )
        )

    # print the scan name if this is a tty out
    return '\n'.join(
        '\t'.join(n)
        for n in sorted(
                ((str(s['id']), s['name']) for s in scans),
                reverse=descending
        )
    )

def subcommands(subparsers):
    folder = subparsers.add_parser('folder', help='Routines for getting metadata out of a nessus folder')
    folder.add_argument('folder', type=int, help='Folder to read')

    subcommands = folder.add_subparsers()
    scans = subcommands.add_parser('scans', help='List the scans in the folder')
    scans.add_argument('-d', '--descending', action='store_true',
                       help='set to reverse order of list')
    scans.set_defaults(func=folder_scans)

    
    
    
