# Pynigma

This project started as a means of replicating the idea of the Enigma Machine in python, and was modified to be _better_. Simply put, it is an encryption algorithm based on a complex series of reflective substitution ciphers. How is it better than the Enigma Machine? Well for starters the character set is considerably larger, and there is no specific limit on the amount of rotors needed to perform the substitution cipher. They are randomly generated and applied with arbitrary shift numbers which can tell a rotor to "rotate" _shift_ amount of times per character.

The general idea of Enigma was that it looked like a typewriter that when a key is pressed, a light bulb will turn on a corresponding lettered bulb denoting the new letter. When typing out your plaintext, you would write down the ciphertext produced by the light bulbs.

On a more specific pattern, when a key is pressed, it first goes through a plugboard which was a static substitution cipher. So A => B, C => J, etc. Then the result of this was passed through a rotor which itself was a substitution cipher, but once the key was pressed the first rotor would rotate once and become a new substitution cipher. It would then take the result of the substitution and send it to the next rotor, then the third, and through a reflection plate which would substitute a letter again and send it back through rotor 3, then 2, then 1, back through the initial plugboard and to the corresponding light bulb. If rotor 1 made a full cycle, it would then rotate rotor 2 once and so on.

My script works similarly, but instead of using a reflection plate you could simply use another rotor, which worked as a dynamically linked list, pointing to the next rotor in succession until it hit the final rotor, and then it simply moved back down the rotor list and through the plugboard again.

The elegance of this cipher is that there is no "decrypt" function necessary. If you set up a new instance of the enigma machine with a rotor setting and produce ciphertext, the intended party would have to know the enigma settings as well, and simply enter the ciphertext in as the input and it would transpose the ciphertext back into plaintext. It is completely reflective!

**I would strongly suggest you not rely on this for extremely sensitive information**. This would inevitably be the Nazi's downfall after all. This cipher is every bit as vulnerable as the original Enigma cipher, as every single letter transposed will _never_ transpose back to itself. Regardless, maybe this could be useful for a CTF or something?

## Usage

**First, generate a key.** The key is literally a compressed set of instructions and rotor configurations for the enigma machine, organized in such a way that mimics SSH Private Keys.

```python
import enigma

my_key = enigma.generate_key()
```

**Write the key to a file.** You can write the key to a file for later usage if you want.

```python
import enigma

my_key = enigma.generate_key()
enigma.write_key_file(my_key, 'my_key.key')
```

**Read the key from a file.** You can read the key as well as long as it is formatted properly.

```python
import enigma

my_key = enigma.read_key_file('my_key.key')
```

**Get your secret message.** Load a new instance of the Enigma object and use the `transpose()` function.

```python
import enigma

my_key = enigma.read_key_file('my_key.key')
e = enigma.Enigma(my_key)

my_cipher = e.transpose("Hello, World!")

print(my_cipher)

# Prints: "3/M3u@WPb9VLu"
```

**Decode the ciphertext.** Assuming you have the key used to generate the ciphertext, you can use it to transpose the ciphertext and it will print out the plaintext!

```python
import enigma

my_key = enigma.read_key_file('my_key.key')
e = enigma.Enigma(my_key)

my_plaintext = e.transpose('3/M3u@WPb9VLu')
print(my_plaintext)

# Prints: "Hello, World!"
```