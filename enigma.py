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
import yaml

charset = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS' \
          'TUVWXYZ !@#$%^&*()\'",./:;'


def int_to_roman(number):
    """
    Shamelessly stolen from O'Reilly. I just thought it was cool. Converts
    an integer to a roman numeral. This is useful for automatically naming
    the rotors.
    """
    if not isinstance(number, type(1)):
        raise TypeError(f"expected integer, got {type(number)}")
    if not 0 < number < 4000:
        raise ValueError("Argument must be between 1 and 3999")
    ints = (1000, 900, 500, 400, 100, 90, 50, 40, 10, 9, 5, 4, 1)
    nums = ('M', 'CM', 'D', 'CD', 'C', 'XC', 'L', 'XL', 'X', 'IX', 'V', 'IV', 'I')
    result = []
    for i in range(len(ints)):
        count = int(number / ints[i])
        result.append(nums[i] * count)
        number -= ints[i] * count
    return ''.join(result)


class EnigmaKey:
    def __init__(self, key):
        """
            Takes the enigma key defined in keyformat which has been deciphered
            and broken down using the read_key() function, which returns a complex
            python object. This object will then be used to create the enigma
            machine used to encrypt (and decrypt!) plaintext.
        """
        self.key = key
        self.rotors = []
        first = True
        for r in self.key["rotors"]:
            if first:
                self.rotors.append(URotor(tpose=r['rotor'],
                                   start=r['start'], shift=r['shift']))
                first = False
            else:
                self.rotors.append(URotor(tpose=r['rotor'], start=r['start'],
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


class EnigmaYaml:
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


class URotor:
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
