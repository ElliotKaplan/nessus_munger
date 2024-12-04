import sys

def folder_list(nessus_session, clargs):
    resp = nessus_session.get('folders')
    flist = resp.json()['folders']
    sortkey = 'name' if clargs.alphasort else 'id'
    flist.sort(key=lambda d: d[sortkey], reverse=clargs.descending)

    if not sys.stdout.isatty():
        return ' '.join(str(d['id']) for d in flist)

    return '\n'.join(f'{d["id"]}\t{d["name"]}' for d in flist)

def subcommands(subparsers):
    list_folders = subparsers.add_parser('list_folders', help='list folders on server')
    list_folders.add_argument('-d', '--descending', action='store_true', help='set to reverse order')
    list_folders.add_argument('-a', '--alphasort', action='store_true', help='set to sort output by folder name')
    list_folders.set_defaults(func=folder_list)
    
