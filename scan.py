import argparse
from os import environ

from subcommands import folder, scan
from classes.nessus_session import NessusSession

if __name__ == '__main__':
    argparser = argparse.ArgumentParser('Utility routines for dealing with Nessus scans')
    argparser.add_argument('--nessus_host', type=str, default=environ.get('NESSUS_HOST', 'localhost'))
    argparser.add_argument('--access_key', type=str, default=environ.get('ACCESS_KEY', ''))
    argparser.add_argument('--secret_key', type=str, default=environ.get('SECRET_KEY', ''))
    argparser.add_argument('--nessus_port', type=int, default=environ.get('NESSUS_PORT', 8834))

    subparsers = argparser.add_subparsers()
    folder.subcommands(subparsers)
    scan.subcommands(subparsers)

    clargs = argparser.parse_args()
    
