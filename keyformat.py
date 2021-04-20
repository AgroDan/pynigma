#!/usr/bin/env python3

"""
    This file will attempt to build and work with a "key format"
    that I will implement for pynigma. This key will effectively
    work similarly to symmetric key encryption, because not only
    will you be able to encrypt plaintext with it, you can decrypt
    the ciphertext back to the plaintext with it as well. The way
    that this works is not that this is a "key" per se, but is actually
    a compressed and encoded list of instructions for the pynigma
    engine to use.

    The basic format is a base64 encoded json list:

    {
        name: <name of enigma machine instance>,
        plugboard: <name of plugboard> <-- may remove this
        plugformat: <plugformat applied to plugboard>
        rotors: [
            0: {
                name: <name of left-most rotor>
                start: <starting pos of rotor>
                shift: <shift value of rotor>
                rotor: {
                    <base64-encoded and zlib compressed rotor substitution dict>
                }
                checksum: <sha256 hash of rotor>
            }
            1: {
                etc etc etc
            }
        ]
    }
"""

# Will make a better random function, but for now this will get the job done
import random
import json
import hashlib
import base64
from enigma import charset
import zlib

def generate_key(max_plugs=20, max_rotors=10):
    """
        Generates a "key" for the pynigma cipher.
    """

    # Some assertions:
    try:
        assert max_plugs%2 == 0
    except AssertionError:
        raise Exception("max_plugs must be divisible by 2!")

    try:
        assert len(charset)%2 == 0
    except AssertionError:
        raise Exception("Charset length must be divisible by 2!")

    # Build the plugboard
    p = [c for c in charset]
    plugformat = ''
    plugsample = random.sample(p, random.randrange(int(max_plugs/2),max_plugs,2))
    # print(plugsample)
    for i in range(0, len(plugsample), 2):
        # print(f"I : {i}")
        if len(plugformat):
            plugformat += f"|{plugsample[i]}-{plugsample[i+1]}"
        else:
            plugformat += f"{plugsample[i]}-{plugsample[i+1]}"

    # Build the rotors
    rotors = []
    for rotor in range(max_rotors):
        r = [c for c in charset]
        random.shuffle(r)
        left = [c for c in r[:int(len(r)/2)]]
        right = [c for c in r[int(len(r)/2):]]
        transpose_table = {}
        for i,j in zip(left,right):
            transpose_table[i] = j
            transpose_table[j] = i
        r_setting = zlib.compress(json.dumps(transpose_table).encode('utf-8'))
        m = hashlib.sha512()
        m.update(r_setting)
        checksum = m.hexdigest()
        rotors.append({'rotor': base64.b64encode(r_setting).decode(),
                       'checksum': checksum,
                       'start': random.randrange(1, len(charset)),
                       'shift': random.randrange(1, int(len(charset)/2))})

    # Now put it all together

    result = { "plugboard": json.dumps(plugformat), "rotors": json.dumps(rotors) }
    result = json.dumps(result).encode('utf-8')
    return base64.b64encode(zlib.compress(result))


def read_key(key):
    """
    Unpacks and reads the key for usage with Enigma. This is done in this file
    so the libraries don't need to be imported again.
    """
    # First, b64decode and decompress
    key = json.loads(zlib.decompress(base64.b64decode(key)))
    key["plugboard"] = json.loads(key["plugboard"])
    key["rotors"] = json.loads(key["rotors"])

    rotor_array = []

    # Now loop through each rotor
    for r in key["rotors"]:
        gear = {}
        gear['rotor'] = base64.b64decode(r['rotor'])
        m = hashlib.sha512()
        m.update(gear['rotor'])
        if r['checksum'] != m.hexdigest():
            raise Exception("Invalid hash for supplied rotor!")
        else:
            gear['rotor'] = json.loads(zlib.decompress(gear['rotor']))
            gear['start'] = r['start']
            gear['shift'] = r['shift']

        rotor_array.append(gear)

    key["rotors"] = rotor_array
    return key
