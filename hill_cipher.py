# ----------------------------------------------
# Encodes and decodes text (made from a reduced 
# subset of characters) using Hill's algorithm
# ----------------------------------------------

# usage: $python hill_ciphers.py <text> <key> -s <string> -e|-d

# Notes: for the algorithm to work

# Author: Adolfo Acosta Castro
# Date: 2022/11/16

import sys
import math 

# Set up extended alphabet
ALPHABET = []
i = ord('A')
while i <= ord('Z'):
    ALPHABET.append(chr(i))
    i += 1
i = ord('a')
while i <= ord('z'):
    ALPHABET.append(chr(i))
    i += 1
i = ord('0')
while i <= ord('9'):
    ALPHABET.append(chr(i))
    i += 1
    
ALPHABET += [
    'ñ', 'Ñ', 'Á', 'É', 'Í', 'Ó', 'Ú', 'á', 'é', 'í', 'ó', 'ú',
    ' ', ',', '.', '¿', '?', '¡', '!', '$', '*', '+', '-', '/', '#', '\'', '\"']

ALPHABET_LEN = len(ALPHABET)
ENCODE = True
DECODE = False

def letterToNum(letter):
    if letter in ALPHABET:
        return ALPHABET.index(letter)
    print(f"{letter} isn't supported by the alphabet")

def numToLetter(num):
    return ALPHABET[num]

def gcd(a, b):
    '''
    Returns the greatest common divisor of two integers
    using Euclid's algorithm
    '''
    if a == 0:
        return b
    return gcd(b % a, a)

def gcdExtended(a, b):
    '''
    Returns the greatest common divisor of two integers
    and integers x and y such that ax + by = gcd(a, b)
    using Euclid's extended algorithm
    '''
    if a == 0 :
        return b, 0, 1
             
    g, x1, y1 = gcdExtended(b % a, a)
     
    x = y1 - (b // a) * x1
    y = x1
     
    return g, x, y

def det(matrix):
    '''
    Calculates the determinant of a matrix using 
    Laplace expansion. Adapted from:
    https://en.wikipedia.org/wiki/Laplace_expansion   
    '''
    if len(matrix) == 1:
        return matrix[0][0]

    determinant = 0    
    firstRow = matrix[0]
    for column, value in enumerate(firstRow):
        lowerRows = matrix[1:]
        minor = [row[:column] + row[column+1:] for row in lowerRows]
        sign = 1 if column % 2 == 0 else -1
        determinant += sign * value * det(minor)

    return determinant

def mod(num, divisor):
    if num >= 0:
        return (num % divisor)
    return ((divisor - ((-num) % divisor)) % divisor)

class CipherMat:
    mat = None
    rows = 0
    columns = 0

    def stringToMat(self, string):
        '''
        Converts a string's characters to numbers and stores them
        in the cipher matrix
        '''        
        self.rows = self.columns = int(math.sqrt(len(string)))

        if self.rows * self.columns != len(string):
            print("Please use a key of square length")
            sys.exit(0)

        self.mat = []
        
        i = 0
        for row in range(self.rows):
            self.mat.append([])
            for col in range(self.columns):
                self.mat[row].append(letterToNum(string[i]))
                i += 1
    
    def size(self):
        return self.rows

    def inverse(self):
        '''
        Replaces the matrix with its modular inverse
        '''
        # Verify if inverse exists
        determinant = det(self.mat)
        if determinant == 0:
            print("Can't decode because the key matrix isn't invertible (it's determinant is 0)")
            sys.exit(0)
        if abs(gcd(determinant, ALPHABET_LEN)) != 1:
            print("Can't decode because the key matrix isn't invertible (it's determinant isn't coprime with the alphabet length)")
            sys.exit(0)

        # Calculate cofactor matrix
        inverseMat = []
        for row in range(self.rows):
            inverseMat.append([])
            for col in range(self.columns):
                matWithoutCurrentRow = self.mat[:row] + self.mat[row+1:] 
                minor = [row[:col] + row[col+1:] for row in matWithoutCurrentRow]
                sign = 1 if (row + col) % 2 == 0 else -1
                cofactor = sign * det(minor)
                inverseMat[row].append(cofactor)
        
        # Calculate adjoint matrix
        for row in range(self.rows):
            for col in range(row):
                temp = inverseMat[row][col]
                inverseMat[row][col] = inverseMat[col][row]
                inverseMat[col][row] = temp
                
        # Calculate modular inverse matrix
        g, x, y = gcdExtended(mod(determinant, ALPHABET_LEN), ALPHABET_LEN);
        determinantModInverse = mod(x, ALPHABET_LEN);
        for row in range(self.rows):
            for col in range(self.columns):
                inverseMat[row][col] *= determinantModInverse;
                inverseMat[row][col] = mod(inverseMat[row][col], ALPHABET_LEN)
        
        self.mat = inverseMat

    def cipher(self, block):
        '''
        Returns the multiplication of the stored matrix by the block
        '''
        result = []
        for row in range(self.rows):
            result.append(0)
            for col in range(self.columns):
                result[row] += self.mat[row][col] * block[col]
            result[row] = mod(result[row], ALPHABET_LEN)

        return result
        
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


def hillCipher(message, key, encoding = True):
    cipherMat = CipherMat()
    cipherMat.stringToMat(key)
    if not encoding:
        cipherMat.inverse()
    
    i = 0
    transformedMessage = ""
    blockLen = cipherMat.size()

    if len(message) % blockLen != 0:
        missingLen = blockLen - (len(message) % blockLen) 
        message += ' ' * missingLen

    while i < len(message):
        plainBlock = []
        for j in range(blockLen):
            plainBlock.append(letterToNum(message[i]))
            i += 1
        
        cipheredBlock = cipherMat.cipher(plainBlock)
        for j in range(blockLen):
            transformedMessage += numToLetter(cipheredBlock[j])
        
    return transformedMessage

def testCipher(message, key):
    cipheredText = hillCipher(message, key, ENCODE)
    decipheredText = hillCipher(cipheredText, key, DECODE)
    assert(message == decipheredText.strip())
            
def testCiphers():
    keys = [
        'TWOK', 'HELL', 
        'NINECHARS', 'LONGERKEY', 'THREE KEY',
        'I AM INVERTIBLE?',
        'FIVE BY FIVE KEY LONG KEY'
    ]
    texts = [
        'My name is Yoshikage Kira. I\'m 33 years old. My house is in the northeast section of Morioh, where all the villas are, and I am not married. I work as an employee for the Kame Yu department stores, and I get home every day by 8 PM at the latest. I don\'t smoke, but I occasionally drink. I\'m in bed by 11 PM, and make sure I get eight hours of sleep, no matter what. After having a glass of warm milk and doing about twenty minutes of stretches before going to bed, I usually have no problems sleeping until morning. Just like a baby, I wake up without any fatigue or stress in the morning. I was told there were no issues at my last check-up. I\'m trying to explain that I\'m a person who wishes to live a very quiet life. I take care not to trouble myself with any enemies, like winning and losing, that would cause me to lose sleep at night. That is how I deal with society, and I know that is what brings me happiness. Although, if I were to fight I wouldn\'t lose to anyone.',
        'Are you kidding ??? What the **** are you talking about man ? You are a biggest looser i ever seen in my life ! You was doing **** in your **** when i was beating players much more stronger then you! You are not proffesional, because proffesionals knew how to lose and congratulate opponents, you are like a girl crying after i beat you! Be brave, be honest to yourself and stop this trush talkings!!! Everybody know that i am very good blitz player, i can win anyone in the world in single game! And "w"esley "s"o is nobody for me, just a player who are crying every single time when loosing,  remember what you say about Firouzja  !!! Stop playing with my name, i deserve to have a good name during whole my chess carrier, I am Officially inviting you to OTB blitz match with the Prize fund! Both of us will invest 5000$ and winner takes it all! I suggest all other people who\'s intrested in this situation, just take a look at my results in 2016 and 2017 Blitz World championships, and that should be enough... No need to listen for every crying babe, Tigran Petrosyan is always play Fair ! And if someone will continue Officially talk about me like that, we will meet in Court! God bless with true! True will never die ! Liers will kicked off...',
        'My grandfather smoked his whole life. I was about 10 years old when my mother said to him, \'If you ever want to see your grandchildren graduate, you have to stop immediately\' .Tears welled up in his eyes when he realized what exactly was at stake. He gave it up immediately.Three years later he died of lung cancer. It was really sad and destroyed me. My mother told me- \'Don\'t ever smoke. Please dont put your family through what your Grandfather put us through.\' I agreed. At 28, I have never touched a cigarette. I must say, I feel a very slight sense of regret for never having done it, because your post gave me cancer anyway.'
    ]
    for key in keys:
        for text in texts:
            testCipher(text, key)


text = sys.argv[1]
key = sys.argv[2]
mode = sys.argv[3]

text = text
key = key
mode = ENCODE if mode == "-e" else DECODE

processedString = hillCipher(text, key, mode)
print(processedString)

testCiphers()