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
will be cyclical and
"""

# I am well aware of the implications of using MT19927 as the 
# PRNG here. Then again, I'm making enigma so whatever
import random
import json

class PlugBoard:
    def __init__(self, name, plugformat=None):
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
        self.name = name
        self.plugformat = plugformat
        self.charset = '0123456789abcdefghijklmnopqrstuvwxyz' \
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ !@#$%^&*()\'",./:;'
        self.transpose_table = {}
        self._build_plugboard()
    
    def _build_plugboard(self):
        """
        As stated, this builds the plugboard based on the plugformat
        string.
        """
        if self.plugformat is None:
            # No substitution, call it a day.
            for c in self.charset:
                self.transpose_table[c] = c
        else:
            # Read in the plugformat here.
            # split on |, loop through each
            # split on -, transpose those
            # also transpose the inverse
            # Then loop through each item in the charset afterwards
            # and check if it's been transposed yet. If so, skip and
            # move onto the next one.



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
        self.charset = '0123456789abcdefghijklmnopqrstuvwxyz' \
                       'ABCDEFGHIJKLMNOPQRSTUVWXYZ !@#$%^&*()\'",./:;'
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
