#!/usr/bin/env python3

"""
This file will allow encoding to be performed at the command line.
"""

import argparse

parser = argparse.ArgumentParser(description="Encode or Decode with PyNigma!")

parser.add_argument('-e', '--encode', '--decode', metavar="Encode",
                    type=str, help="Encode or Decode a file. "\
                    "Defaults to STDOUT if -o is not given.")
parser.add_argument('-o', '--output', metavar='OutFile', type=str,
                    help="The file to write the output to.")
parser.add_argument('-g', '--generate', metavar='keyfile')

# Will finish this later, maybe. I hate argparse.