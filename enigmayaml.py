#!/usr/bin/env python3

"""
This file is the enigma code designed to read config and keys from
a yaml file, rather than a key.
"""

import random
import json
import yaml


charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS' \
          'TUVWXYZ !@#$%^&*()\'",./:;'


class Enigma:
    def __init__(self, yaml_file):
        """
        This is the function that starts it all up. By loading in
        the config from a yaml file, it builds the plugboard and
        sets up the rotors automatically. This class will also handle
        the state of the machine, allowing this state to be
        transferred over. Note that the state is not the rotor
        settings, but rather the initial rotor states. You would
        need to configure the rotor state and plugboard settings in
        a separate function to be used for encryption.
        """
        try:
            with open(yaml_file, 'r') as f:
                self.settings = yaml.safe_load(f)
        except FileNotFoundError:
            raise Exception ("YAML file not found!")
        
        # Build the rotor linkage.
        # TODO: maybe include the rotor setup in a state file or something.
        # Maybe use a cryptographic hash to determine if the rotor state is correct?
        self.rotors = []
        first = True
        for r in self.settings['rotors']:
            if first:
                self.rotors.append(Rotor(name=r['name'],
                                         start=r['start'], shift=r['shift']))
                first = False
            else:
                self.rotors.append(Rotor(name=r['name'], start=r['start'],
                                         shift=r['shift'], r=self.rotors[-1]))

        # Build the plugboard
        self.plugboard = PlugBoard(plugformat=self.settings['plugboard']['plugformat'])

        # I will need to make this a global var since everyone uses it, but
        # that's a bridge I'll burn at a later date
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
    def __init__(self, name, start=0, shift=1, r=None):
        """
        name := name of the rotor, usually I, II, III, IV, etc
        start := what position to set the rotor to
        r := pointer to another initialized rotor instance, this
             is the rotor next in line
        """
        self.name = name
        self.start = start
        self.current = start
        self.shift = shift
        self.next_rotor = r
        self.charset = charset
        try:
            with open(f"{self.name}.enigma", "r") as f:
                self.transpose_table = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._build_transpose_table()
        self._turn_rotor(self.start)

    def _build_transpose_table(self):
        r = [c for c in self.charset]
        random.shuffle(r)
        left = [c for c in r[:int(len(r)/2)]]
        right = [c for c in r[int(len(r)/2):]]
        self.transpose_table = {}
        for i,j in zip(left,right):
            self.transpose_table[i] = j
            self.transpose_table[j] = i
        # self.transpose_table = {}
        # for i, char in enumerate(self.charset):
        #     self.transpose_table[char] = r[i]
        with open(f"{self.name}.enigma", "w") as f:
            json.dump(self.transpose_table, f)

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
            # This would otherwise seem to cancel each other out, but
            # because the final rotor serves as a reflection plate,
            # it will continue to transpose even further back up the
            # chain, and still remain
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