#!/usr/bin/env python3

"""
This is my attempt at writing my own enigma machine.

The basic principle is thus:

There are X rotors Rotor 1 spins until it cycles completely,
then spins rotor 2, when it cycles completely it spins rotor 3.
Each rotor is simply a mapping of 1 letter to another letter. This
is randomly generated and written out as files.

When a letter is pressed in the enigma machine, it is first substituted
with another letter based on a plugboard. The result then goes through
the first set of rotors before it is turned around with a reflector 
to go back through the rotors again and through the plugboard to result
in one letter. Note that here there is no reason to include a reflector,
but to emulate (in a better sense) the way that Enigma works, you can
simply use an additional rotor. As long as the rotors are linked, they
will be cyclical and each supplied character will have its compliment.
A = B and B = A and so on.
"""

# I am well aware of the implications of using MT19927 as the 
# PRNG here. Then again, I'm making enigma so whatever
import random
import json
import hashlib
import base64
import zlib

charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS' \
          'TUVWXYZ !@#$%^&*()\'",./:;'

"""
    These next few functions will attempt to build and work with
    a "key format" for pynigma. This key will effectively work
    similarly to symmetric key encryption, because not only will you
    be able to encrypt plaintext with it, you can decrypt the ciphertext
    back to the plaintext with it as well. The way that this works is
    not that this is a "key" per se, but is actually a compressed and
    encoded list of instructions for the pynigma engine to use.

    The basic format is a base64 encoded json list:

    {
        plugboard: <plugformat applied to plugboard>
        rotors: [
            0: {
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


class Enigma:
    def __init__(self, key):
        """
            Takes the enigma key defined in keyformat which has been deciphered
            and broken down using the read_key() function, which returns a complex
            python object. This object will then be used to create the enigma
            machine used to encrypt (and decrypt!) plaintext.
        """
        self.key = read_key(key)
        self.rotors = []
        first = True
        for r in self.key["rotors"]:
            if first:
                self.rotors.append(Rotor(tpose=r['rotor'],
                                   start=r['start'], shift=r['shift']))
                first = False
            else:
                self.rotors.append(Rotor(tpose=r['rotor'], start=r['start'],
                                          shift=r['shift'], r=self.rotors[-1]))

        # Build the plugboard
        self.plugboard = PlugBoard(plugformat=self.key['plugboard'])
        self.charset = charset

    def transpose(self, data):
        """
            Does the actual transposition of each individual letter.
        """
        res = ''
        for c in data:
            if c in self.charset:
                r = self.plugboard.transpose(c)
                r = self.rotors[-1].rotate(r)
                r = self.plugboard.transpose(r)
                res += r
            else:
                res += c
        return res


class PlugBoard:
    def __init__(self, plugformat=None):
        """
        Initializes a plugboard. The plugboard is a substitution cipher
        that is fixed. It accepts a string as the plugformat parameter,
        which should be specified as 'A-B|C-D|E-J' etc. The first letter
        followed by a dash, then the letter it will transpose to. Note
        that overlaps will be met with an Exception, so A -> B and B -> C
        will throw an error and refuse to run. The plugformat must be
        cyclical! A = B and B = A. An exception will be thrown if so.
        The plugformat will be read in and missing letters will not be
        transposed, but if one letter is transposed its compliment will
        be transposed back automatically.
        """
        self.plugformat = plugformat
        self.charset = charset
        self.transpose_table = {}
        self._build_plugboard()
    
    def _build_plugboard(self):
        """
        As stated, this builds the plugboard based on the plugformat
        string.
        """
        # Zero this out just to be certain
        self.transpose_table = {}

        if self.plugformat is None:
            # No substitution, call it a day.
            for c in self.charset:
                self.transpose_table[c] = c
        else:
            try:
                for inst in self.plugformat.split('|'):
                    if len(inst) == 3:
                        i_from, i_to = inst.split('-')
                        if i_from in self.transpose_table or i_to in self.transpose_table:
                            # We have overlap!
                            raise Exception("Overlap in plugboard format!")
                        self.transpose_table[i_from] = i_to
                        self.transpose_table[i_to] = i_from
            except ValueError:
                raise Exception("Please follow plugformat of a-b|c-d|d-e")
            finally:
                for c in self.charset:
                    if c not in self.transpose_table:
                        self.transpose_table[c] = c

    def transpose(self, c):
        """
        The official function to transpose a letter via the plugboard
        """
        return self.transpose_table[c]


class Rotor:
    def __init__(self, tpose, start=0, shift=1, r=None):
        """
        Unnamed Rotor. This is a rotor that does not generate
        a transpose table, but rather receives one as a parameter.
        This will never write or read anything from disk.
        tpose := The transpose table sent as a parameter to this
                 object
        start := what position to set the rotor to
        shift := how many positions to shift for each rotation
        r := pointer to another initialized rotor instance, this
             is the rotor next in line
        """
        self.transpose_table = tpose
        self.start = start
        self.current = start
        self.shift = shift
        self.next_rotor = r
        self.charset = charset
        self._turn_rotor(self.start)

    def _turn_rotor(self, amount):
        """
        Does nothing but turn the rotor <amount> times. Used for setting the
        rotor.
        """
        # Rotate the rotor
        r_charset = [self.transpose_table[k] for k in self.transpose_table]
        r_charset = r_charset[amount%len(self.charset):] + r_charset[:amount%len(self.charset)]
        left = [c for c in r_charset[:int(len(r_charset)/2)]]
        right = [c for c in r_charset[int(len(r_charset)/2):]]
        self.transpose_table = {}
        for i,j in zip(left,right):
            self.transpose_table[i] = j
            self.transpose_table[j] = i

        # for i,item in enumerate(self.charset):
        #     self.transpose_table[item] = r_charset[i]

    def transpose(self, c):
        """
            Does not rotate a rotor, just tranposes
        """
        if self.next_rotor is None:
            return self.transpose_table[c]
        else:
            # This may technically cancel each other out, but ONLY if the rotor
            # does not move. This allows the circuit to route through all the
            # rotors AND BACK AGAIN.
            return self.transpose_table[self.next_rotor.transpose(self.transpose_table[c])]


    def rotate(self, c):
        """
        c := the character to get transposed
        """
        self._turn_rotor(self.shift)
        self.current += self.shift

        # If there is another rotor down the line, send the new transpose
        if self.current > len(self.charset):
            self.current %= len(self.charset)
            if self.next_rotor is None:
                return self.transpose_table[c]
            else:
                return self.transpose_table[self.next_rotor.rotate(self.transpose_table[c])]
        else:
            if self.next_rotor is None:
                return self.transpose_table[c]
            else:
                return self.transpose_table[self.next_rotor.transpose(self.transpose_table[c])]
