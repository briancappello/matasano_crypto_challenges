from string import ascii_lowercase as alphabet_lower
alphabet_upper = alphabet_lower.upper()
numbers = '0123456789'

def chunk(string, size):
    for i in xrange(0, len(string), size):
        yield string[i:i+size] 

## CHALLENGE 1: Convert hex to base64 ##
'''
The string:
49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:
SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
'''

### ASCII ##
def ascii_to_binary(string):
    ret = ''
    for char in string:
        ret += bin(ord(char))[2:].zfill(8)
    return ret

def binary_to_ascii(string):
    ret = ''
    for char in chunk(string, 8):
        ret += chr(int(char, 2))
    return ret


### HEX ##
def hex_to_binary(string):
    ret = ''
    for char in string:
        ret += bin(int(char, 16))[2:].zfill(4)
    return ret

def binary_to_hex(string):
    ret = ''
    for val in chunk(string, 4):
        ret += hex(int(val, 2))[-1]
    return ret


### BASE64 ##
def base64_to_binary(string):
    ret = []
    for char in string:
        if char in alphabet_upper:
            ret.append(ord(char) - 65)
        elif char in alphabet_lower:
            ret.append(ord(char) - 71)
        elif char in numbers:
            ret.append(ord(char) + 4)
        elif char == '+':
            ret.append(62)
        elif char == '-':
            ret.append(63)
    return ''.join(map(lambda x: bin(x)[2:].zfill(6), ret))

def binary_to_base64(string):
    ret = ''
    for binary in chunk(string, 6):
        val = int(binary, 2)
        if val <= 25:                  # upper case letters
            ret += chr(val + 65)
        elif val >= 26 and val <= 51:  # lower case letters
            ret += chr(val + 71) 
        elif val >= 52 and val <= 61:  # numbers
            ret += chr(val - 4)
        elif val == 62:
            ret += '+'
        elif val == 63:
            ret += '-'    
    return ret


### HEX TO
def hex_to_ascii(string):
    return binary_to_ascii(hex_to_binary(string))

def hex_to_base64(string):
    return binary_to_base64(hex_to_binary(string))

### BASE64 TO

### ASCII TO

def ascii_to_hex(string):
    return binary_to_hex(ascii_to_binary(string))

def ascii_to_base64(string):
    return binary_to_base64(ascii_to_binary(string))

def base64_to_ascii(string):
    return binary_to_ascii(base64_to_binary(string))

def base64_to_hex(string):
    return binary_to_hex(base64_to_binary(string))


## CHALLENGE 2: Fixed XOR ##
'''
Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:
1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:
686974207468652062756c6c277320657965
... should produce:
746865206b696420646f6e277420706c6179
'''

def binary_xor(binary1, binary2):
    ret = ''
    for pair in zip(binary1, binary2):
        ret += '0' if pair[0] == pair[1] else '1'
    return ret

def hex_xor(string1, string2):
    binary1 = hex_to_binary(string1)
    binary2 = hex_to_binary(string2)
    return binary_to_hex(binary_xor(binary1, binary2))


## CHALLENGE 3: Single-byte XOR cipher ##
'''
The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.
You can do this by hand. But don't: write code to do it for you.
How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score. 
'''
def solve_xor_cipher(cipher_text):
    binary1 = hex_to_binary(cipher_text)
    cribs = []

    for num in xrange(0, 128):
        key = chr(num)
        binary2 = ascii_char_to_binary(key) * (len(binary1)/8)
    
        xor_ = binary_xor(binary1, binary2)
        crib = binary_to_ascii(xor_)
        cribs.append([key, crib, score_text(crib)])

    cribs.sort(key=lambda x: x[2])
    return cribs[-1]

def score_text(string):
    frequency = list(reversed(' etaoinshrdlcumwfgypbvkjxqz'))
    punc = ',.;:\'"!@#$%^&*=+-_<>/?\\'

    total_points = 0    
    for char in string:
        if char in frequency:
            total_points += frequency.index(char) + 1
        elif char in punc:
            total_points += 5
        elif char in numbers:
            total_points += 2

    return total_points


## CHALLENGE 4 Detect single-character XOR ##
'''
One of the 60-character strings in /home/brian/matasano_crypto_challange_s1c4.txt
has been encrypted by single-character XOR.
Find it.
'''

def find_the_crib():
    with open('/home/brian/matasano_crypto_challange_s1c4.txt') as f:
        lines = f.read().splitlines()
    
    results = []
    for line in lines:
        results.append(solve_xor_cipher(line))
    results.sort(key=lambda x: x[2])
    
    return results


## CHALLENGE 5: Implement repeating-key XOR ##
'''
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

'''

crib = 'Burning \'em, if you ain\'t quick and nimble\nI go crazy when I hear a cymbal'
#        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272__a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242727652720aa282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
result = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272  a 28 2b 2f 20 43 0a 652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
def repeating_key_xor(crib, key='ICE'):
    len_ = len(crib)
    key_ = key * (len_/len(key)) + key[:len_ % len(key)]
    xor_ = binary_xor(ascii_to_binary(crib), ascii_to_binary(key_))
    
    return binary_to_hex(xor_)

def decrypt_repeating_key_xor(hex_cipher_text, key):
    len_ = len(crib)
    key_ = key * (len_/len(key)) + key[:len_ % len(key)]
    xor_ = hex_xor(hex_cipher_text, ascii_to_hex(key_))
    
    return hex_to_ascii(xor_)


## CHALLENGE 6 ##

"""
 There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    
    
    
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    
    Solve each block as if it was single-character XOR. You already have code to do this.
    
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important. 
"""

def get_ch6_file():
    with open('/home/brian/matasano_crypto_challange_s1c6.txt') as f:
        return base64_to_binary(f.read())

def hamming_dist(string1, string2):
    return sum(map(int, binary_xor(string1, string2)))

def test():
    return hamming_dist(ascii_to_binary('this is a test'), ascii_to_binary('wokka wokka!!!'))

def do_each_keysize():
    def get_normalized_keysize(binary, keysize):
        first = binary[:keysize*8]
        second = binary[keysize*8:keysize*16]
        return hamming_dist(first, second) / keysize
    
    binary = get_ch6_file()
    keysizes = [(x, get_normalized_keysize(binary, x)) for x in xrange(2, 40)]
    keysizes.sort(key=lambda x: x[1])
    print keysizes
    
def transpose_blocks(ciphertext):
    
