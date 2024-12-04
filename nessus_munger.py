#!/usr/bin/python3

import argparse
from os import environ

from subcommands import folder, scan
from classes.nessus_session import NessusSession, NessusScanSession

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

    clargs = argparser.parse_args()

    try:
        nessus_session = NessusScanSession(clargs.scan, clargs.nessus_host, clargs.access_key, clargs.secret_key, clargs.nessus_port)
    except AttributeError:
        nessus_session = NessusSession(clargs.nessus_host, clargs.access_key, clargs.secret_key, clargs.nessus_port)
    print(clargs.func(nessus_session, clargs))
