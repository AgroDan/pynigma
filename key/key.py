from mtprime import MT19937Prime
import zlib
import hashlib

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