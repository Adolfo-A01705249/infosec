# -------------------------------------------------------------------
# Encodes and decodes strings of letters from the spanish alphabet  |
# with one the following algorithms:                                |
#   -Caesar's cipher                                                |
#   -Vignere's cipher                                               |        
#   -Hill's cipher                                                  |
# In the case of Hill's cipher the block length is fixed to 2       |
# -------------------------------------------------------------------

# usage: $python ciphers.py [-h] -c {caesar,vignere,hill} -m {encode,decode} -s <string> -k <key>

# Author: Adolfo Acosta Castro
# Date: 2022/09/27

import sys
import argparse

ALPHABET_OFFSET = ord('A')
ALPHABET_LEN = 27
ENCODE = True
DECODE = False

def letterToNum(letter):
    if letter < 'A' or letter > 'Z' and letter != 'Ñ':
        print(f"{letter} is not a valid letter")
        sys.exit(0)
    
    if letter <= 'N':
        return (ord(letter) - ALPHABET_OFFSET)
    elif letter == 'Ñ':
        return (ord('N') - ALPHABET_OFFSET + 1)
    else:
        return (ord(letter) - ALPHABET_OFFSET + 1)

def numToLetter(num):
    if num <= letterToNum('N'):
        return (chr(int(num + ALPHABET_OFFSET)))
    if num == letterToNum('Ñ'):
        return 'Ñ'
    return (chr(int(num + ALPHABET_OFFSET - 1)))

def mod(num, divisor):
    if num >= 0:
        return (num % divisor)
    return ((divisor - ((-num) % divisor)) % divisor)

class TwoByTwoCipherMat:
    mat = [[0, 0], [0, 0]]
    rows = 2
    columns = 2

    def multiplyByScalar(self, scalar):
        '''
        Replaces each matrix element by the result of multiplying it 
        by a scalar
        '''
        for row in range(self.rows):
            for col in range(self.columns):
                self.mat[row][col] *= scalar

    def multiplyByTwoByOne(self, twoByOneMat):
        '''
        Returns the result of multiplying the matrix by a 2x1 vector
        without changing the matrix
        '''
        a = self.mat[0][0] * twoByOneMat[0][0] + self.mat[0][1] * twoByOneMat[1][0]
        b = self.mat[1][0] * twoByOneMat[0][0] + self.mat[1][1] * twoByOneMat[1][0]
        a = mod(a, ALPHABET_LEN)
        b = mod(b, ALPHABET_LEN)
        return [[a], [b]]

    def mod(self, divisor):
        '''
        Replaces each matrix element by its modulus given a divisor
        '''
        for row in range(self.rows):
            for col in range(self.columns):
                self.mat[row][col] = mod(self.mat[row][col], divisor)

    def det(self):
        '''
        Return the determinant of the matrix
        '''
        return ((self.mat[0][0] * self.mat[1][1]) - 
                (self.mat[0][1] * self.mat[1][0]))

    def transjacent(self):
        '''
        Replaces the matrix with the transpose of its adjacent
        '''
        # Swap main diagonal
        temp = self.mat[0][0]
        self.mat[0][0] = self.mat[1][1]
        self.mat[1][1] = temp
        
        # Negate elements on the other diagonal
        self.mat[0][1] *= -1
        self.mat[1][0] *= -1

    def stringToMat(self, string):
        '''
        Converts a four letter string to numbers and stores them
        in the matrix
        '''
        i = 0
        for row in range(self.rows):
            for col in range(self.columns):
                self.mat[row][col] = letterToNum(string[i])
                i += 1
        
    def toTheMinusOne(self):
        '''
        Replaces the matrix with its "inverse" defined as:
        K^-1 = [T_ADJ(K)*[(n+1)/det(K)]] mod n
        '''
        self.transjacent()
        det = self.det()
        if det == 0:
            print("Can't continue determinant is zero")
            sys.exit(0)
        self.multiplyByScalar((ALPHABET_LEN + 1) / det)
        self.mod(ALPHABET_LEN)

    def printMatrix(self, message):
        '''
        Prints the matrix numeric values
        '''
        print(message)
        for row in range(self.rows):
            for col in range(self.columns):
                print(f"{self.mat[row][col]} ", end="")
            print("")
        print("")

    def printString(self):
        '''
        Prints the string that the matrix numeric values represent
        '''
        for row in range(self.rows):
            for col in range(self.columns):
                print(numToLetter(self.mat[row][col]), end="")
        print("")

def caesarCipher(message, key, encoding = True):
    transformedMessage = ""
    sign = 1 if encoding else -1
    for letter in message:
        num = letterToNum(letter)
        num = mod(num + (key * sign), ALPHABET_LEN)
        transformedMessage += numToLetter(num)
    return transformedMessage

def vignereCipher(message, key, encoding = True):
    transformedMessage = ""
    sign = 1 if encoding else -1
    j = 0
    for i in range(len(message)):
        letter = message[i]
        num = letterToNum(letter)
        num = mod(num + (letterToNum(key[j]) * sign), ALPHABET_LEN)
        transformedMessage += numToLetter(num)
        j = (j + 1) % len(key)
    return transformedMessage

def hillCipher(message, key, encoding = True):
    transformedMessage = ""
    myMat = TwoByTwoCipherMat()
    myMat.stringToMat(key)
    if not encoding:
        myMat.toTheMinusOne()
    i = 0
    while i < len(message):
        a = letterToNum(message[i])
        b = letterToNum(message[i + 1])
        block = myMat.multiplyByTwoByOne([[a], [b]])
        a = numToLetter(block[0][0])
        b = numToLetter(block[1][0])
        transformedMessage += a + b
        i += 2
    return transformedMessage


parser = argparse.ArgumentParser(description='Encodes and decodes strings from the spanish alphabet with classic ciphers')

parser.add_argument("-c", "--cipher", help = "Cipher algorithm name", choices=['caesar', 'vignere', 'hill'], required = True)
parser.add_argument("-m", "--mode", help = "Mode of the cipher", choices=['encode', 'decode'], required = True)
parser.add_argument("-s", "--string", help = "The string to pass through the algorithm", required = True)
parser.add_argument("-k", "--key", help = "The cipher key", required = True)

args = parser.parse_args()

cipher = None
mode = None
string = args.string.strip().upper()
key = args.key

if args.cipher == "caesar":
    cipher = caesarCipher
    if not args.key.isdigit():
        print("The key has to be an integer for the caesar cipher")
        sys.exit(0)
    key = int(args.key)
elif args.cipher == "vignere":
    cipher = vignereCipher
elif args.cipher == "hill":
    cipher = hillCipher

if args.mode == "encode":
    mode = ENCODE
elif args.mode == "decode":
    mode = DECODE

print(cipher(string, key, mode))

'''
assert(caesarCipher("MEXICANFLAG", 6, ENCODE) == "RKDÑIGSLQGM")
assert(caesarCipher("SLALHV", 30, DECODE) == "PIXIES")
assert(vignereCipher("WINDOWS", "UNIX", ENCODE) == "QUUAJJA")
assert(vignereCipher("LJEHDV", "GOL", DECODE) == "FUTBOL")
assert(hillCipher("PEAR", "EAFB", ENCODE) == "KDAR")
assert(hillCipher("ZLXD", "KCDB", DECODE) == "BIRD")
'''
