#!/usr/bin/python3

import argparse
from os import environ
import sys

from subcommands import folder, scan, root, launch
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
    argparser.add_argument('--x_api_token', type=str, default=environ.get('X_API_TOKEN', None),
                           help='set to use a "browser" session')
    argparser.add_argument('--x_cookie', type=str, default=environ.get('X_COOKIE', None),
                           help='set to use a "browser" session')

    subparsers = argparser.add_subparsers()
    folder.subcommands(subparsers)
    scan.subcommands(subparsers)
    root.subcommands(subparsers)
    launch.subparsers(subparsers)

    clargs = argparser.parse_args()
    instance_information = (
        clargs.nessus_host,
        clargs.access_key,
        clargs.secret_key,
        clargs.nessus_port,
        clargs.x_api_token,
        clargs.x_cookie
    )
    # this is a kludge to figure out which subcommand was called, and thus which object needs to be generated
    if 'folder' in clargs:
        nessus_session = NessusFolderSession(clargs.folder, *instance_information)
    elif 'scan' in clargs:
        nessus_session = NessusScanSession(clargs.scan, *instance_information)
    else:
        nessus_session = NessusSession(*instance_information)
    # if no function is set, print the help message
    try:
        print(clargs.func(nessus_session, clargs))
    except AttributeError:
        argparser.print_usage()
