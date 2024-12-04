#!/usr/bin/python3

import argparse
from os import environ
import sys

from subcommands import folder, scan, root
from classes.nessus_session import NessusSession, NessusScanSession, NessusFolderSession

# typically there's no verification for nessus certs
from warnings import filterwarnings
filterwarnings('ignore')

if __name__ == '__main__':
    argparser = argparse.ArgumentParser('Utility routines for dealing with Nessus scans')
    argparser.add_argument('--nessus_host', type=str, default=environ.get('NESSUS_HOST', 'localhost'))
    argparser.add_argument('--access_key', type=str, default=environ.get('ACCESS_KEY', ''))
    argparser.add_argument('--secret_key', type=str, default=environ.get('SECRET_KEY', ''))
    argparser.add_argument('--nessus_port', type=int, default=environ.get('NESSUS_PORT', 8834))

    subparsers = argparser.add_subparsers()
    folder.subcommands(subparsers)
    scan.subcommands(subparsers)
    root.subcommands(subparsers)

    clargs = argparser.parse_args()
    # this is a kludge to figure out which subcommand was called, and thus which object needs to be generated
    if 'folder' in clargs:
        nessus_session = NessusFolderSession(clargs.folder, clargs.nessus_host, clargs.access_key, clargs.secret_key, clargs.nessus_port)
    elif 'scan' in clargs:
        nessus_session = NessusScanSession(clargs.scan, clargs.nessus_host, clargs.access_key, clargs.secret_key, clargs.nessus_port)
    else:
        nessus_session = NessusSession(clargs.nessus_host, clargs.access_key, clargs.secret_key, clargs.nessus_port)
    # if no function is set, print the help message
    try:
        print(clargs.func(nessus_session, clargs))
    except AttributeError:
        argparser.print_usage()
