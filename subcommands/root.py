import sys
from getpass import getpass

def folder_list(nessus_session, clargs):
    resp = nessus_session.get('folders')
    flist = resp.json()['folders']
    sortkey = 'name' if clargs.alphasort else 'id'
    flist.sort(key=lambda d: d[sortkey], reverse=clargs.descending)

    if not sys.stdout.isatty():
        return ' '.join(str(d['id']) for d in flist)

    return '\n'.join(f'{d["id"]}\t{d["name"]}' for d in flist)

def session_logon(nessus_session, clargs):
    # accept input for logon 
    username = input("Username: ") if clargs.user is None else clargs.user
    password = getpass("Password: ") if clargs.password is None else clargs.password

    try:
        resp = nessus_session.logon(username, password)
    except AssertionError as err:
        return str(err)
    # intended use is to set environmental variables for use with further calls to scripts
    return f'export X_API_TOKEN={nessus_session.headers["X-API-Token"]}\nexport X_COOKIE={nessus_session.headers["X-Cookie"]}\n'
    

def subcommands(subparsers):
    list_folders = subparsers.add_parser('list_folders', help='list folders on server')
    list_folders.add_argument('-d', '--descending', action='store_true', help='set to reverse order')
    list_folders.add_argument('-a', '--alphasort', action='store_true', help='set to sort output by folder name')
    list_folders.set_defaults(func=folder_list)
    
    logon = subparsers.add_parser(
        'logon',
        help='create a "broswer session". Necessary for actions such as launching or creating scans'
    )
    logon.add_argument('-u', '--user', type=str, default=None, help='username for logon')
    logon.add_argument('-p', '--password', type=str, default=None, help='password for logon')
    logon.set_defaults(func=session_logon)
