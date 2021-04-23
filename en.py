#!/usr/bin/env python3

"""
This file will allow encoding to be performed at the command line.
"""

import argparse
import subcrypt
import sys

parser = argparse.ArgumentParser(description="Encode or Decode a file with PyNigma!")

parser.add_argument('-e', "--encrypt", "--decrypt", action="store", dest="will_enc",
                    help="Encode or Decode a file. Defaults to STDOUT if -o is not given.")
parser.add_argument('-o', '--output', action="store", dest="out", metavar='OutFile', type=str,
                    help="The file to write the output to.")
parser.add_argument('-g', '--generate', action="store", dest="genfile", type=str, metavar='keyfile',
                    help="Generate a key and store it in a file")
parser.add_argument('-r', '--read-key', action="store", dest="readfile", type=str, metavar='keyfile',
                    help="Read a key from a file")

args = parser.parse_args()


if args.out and not args.will_enc:
    print("Incompatible arguments, need something to transpose!")
    exit(1)

if args.will_enc and not (args.genfile or args.readfile):
    print("Incompatible arguments, if no supplied key, where should it be written?")
    exit(1)

# Generate a key regardless, it can be overwritten later
key = subcrypt.generate_key()

if args.genfile:
    subcrypt.write_key_file(key, args.genfile)

if args.readfile:
    key = subcrypt.read_key_file(args.readfile)

if args.will_enc:
    e = subcrypt.Enigma(key)
    with open(args.will_enc, "rb") as f:
        data = f.read()
    result = e.transpose(data)

    if args.out:
        with open(args.out, "wb") as f:
            f.write(result)
    else:
        sys.stdout.write(result)
