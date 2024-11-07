import re
import base64
import struct

def main():
    prompt = userPrompt()
    if prompt == "1":
        encryptedCeasar = notaeCaesarianaeEnc()
        print("Your encrypted text:\n", encryptedCeasar)
    elif prompt == "2":
        encryptedVigenère = chiffre_de_Vigenère_Enc()
        print("Your encrypted text:\n", encryptedVigenère)
    elif prompt == "3":
        encryptedROT13 = rotate_ROT13_Enc()
        print("Your encrypted text:\n", encryptedROT13)
    elif prompt == "4":
        encryptedAtbash = atbash()
        print("Your encrypted text:\n", encryptedAtbash)
    elif prompt == "5":
        encryptedXORASCII, encryptedXORHex = gammyXOR()
        print("Your encrypted text:\nASCII: ", encryptedXORASCII)
        print("\nHex: ", encryptedXORHex)
    elif prompt == "6":
        encryptedROT1 = rot1BroThoughtHeClever()
        print("Your encrypted text:\n", encryptedROT1)
    elif prompt == "7":
        encryptedMorse = morseCode()
        print("Your encrypted text:\n", encryptedMorse)
    elif prompt == "8":
        encryptedBinary = binaryEnc()
        print("Your encrypted text:\n", encryptedBinary)
    elif prompt == "9":
        encryptedBase64 = base64Enc()
        print("Your encrypted text:\n", encryptedBase64)
    elif prompt == "10":
        md2in = input("Type text to encrypt: ")
        encrypted_input = md2(md2in.encode())
        print("Your encrypted text:\n", encrypted_input.hex())
    elif prompt == "11":
        encryptedMD4 = md4()
        print("Your encrypted text:\n", encryptedMD4.hex())
    elif prompt == "12":
        encryptedRailFence = rail_fence()
        print("Your encrypted text:\n", encryptedRailFence)
    elif prompt == "13":
        encryptedTransposition = trans()
        print("Your encrypted text:\n", encryptedTransposition)

def userPrompt():
    whatToDo = input("Do you want to Encrypt or Decrypt?(Type enc for Encryption and dec for decryption:)\n")
    if whatToDo == "enc":
        whichOne = input(
            "Which encryption method do you want to use? Type the corresponding number: \n1. Ceasar\n2. Vigenère Cipher\n3. ROT13\n4. Atbash Cipher"
            "\n5. XOR\n6. ROT1\n7. Morse Code\n8. Binary\n9. Base64\n10. MD2\n11. MD4\n12. Rail-Fence\n13. Transposition\n")
        return whichOne
    elif whatToDo == "dec":
        whichOne1 = input("Type a string/key/or text to decrypt:")
        return whichOne1
    else:
        print("Invalid command.")

def notaeCaesarianaeEnc():
    direction = input("In which direction do you want to shift?(f - Forward, b - backward:\n")
    shift = int(input("By how many digits do you want to shift?\n"))
    cesPrompt = input("Type your key/string or text to encrypt:\n")
    encryptedCeasar = ""
    shiftedEC = 0
    for cestxt in cesPrompt:
        myASCII = ord(cestxt)
        if direction == "f":
            shiftedEC = (myASCII + shift)
        elif direction == "b":
            shiftedEC = (myASCII - shift)
        else:
            print("Incorrect direction.\n")
            return
        if shiftedEC < 32:
            shiftedEC += 95
        elif shiftedEC > 126:
            shiftedEC -= 95
        encryptedCeasar += chr(shiftedEC)
    return encryptedCeasar
# def notaeCaesarianaeDec():


def chiffre_de_Vigenère_Enc():
    vigenèreStrE = input("Type your text to encrypt:\n")
    vigenèreKeyE = input("Type your key:\n")
    encVig = ""
    multKey = vigenèreKeyE * (len(vigenèreStrE) // len(vigenèreKeyE)) + vigenèreKeyE[:len(vigenèreStrE) % len(vigenèreKeyE)]
    for i in range(len(vigenèreStrE)):
        if vigenèreStrE[i].isalpha():
            if vigenèreStrE[i].islower():
                vStrE = ord(vigenèreStrE[i]) - ord('a')
                vKeyE = ord(multKey[i]) - ord('a')
                shiftedVigTemp = (vStrE + vKeyE) % 26
                encVig += chr(shiftedVigTemp + ord('a'))
            else:
                vStrE = ord(vigenèreStrE[i]) - ord('A')
                vKeyE = ord(multKey[i]) - ord('A')
                shiftedVigTemp = (vStrE + vKeyE) % 26
                encVig += chr(shiftedVigTemp + ord('A'))
        else:
            encVig += vigenèreStrE[i]
    return encVig

#def chiffre_de_Vigenère_Dec():

def rotate_ROT13_Enc():
    shiftedROT13 = ""
    rot13txt = input("Type your desired text to encrypt:\n")
    for rot13 in rot13txt:
        if rot13 >= 'a' and rot13 <= 'z':
            shiftedROT13 += chr((ord(rot13) - ord('a') + 13) % 26 + ord('a'))
        elif rot13 >= 'A' and rot13 <= 'Z':
            shiftedROT13 += chr((ord(rot13) - ord('A') + 13) % 26 + ord('A'))
        else:
            shiftedROT13 += rot13
    return shiftedROT13

def atbash():
    atbashtxt = input("Type your desired text to encrypt:\n")
    shiftedAtbash = ""
    for atbashh in atbashtxt:
        if 'a' <= atbashh <= 'z':
            shiftedAtbash += chr(ord('z') - (ord(atbashh) - ord('a')))
        elif 'A' <= atbashh <= 'Z':
            shiftedAtbash += chr(ord('Z') - (ord(atbashh) - ord('A')))
        else:
            shiftedAtbash += atbashh
    return shiftedAtbash

def gammyXOR():
    xortxtE = input("Type your text to encrypt:\n")
    xorkeyE = input("Type your key:\n")
    encXOR = ""
    encXORASCII = ""
    multKey = xorkeyE * (len(xortxtE) // len(xorkeyE)) + xorkeyE[:len(xortxtE) % len(xorkeyE)]
    for i, j in zip(xortxtE, multKey):
        encXORASCIItemp = (ord(i) ^ ord(j))
        encXORASCII2 = (encXORASCIItemp % 95) + 32
        encXORASCII += chr(encXORASCII2)
        encXOR += "\\x" + format(encXORASCIItemp, "02x")
    return encXORASCII, encXOR

def rot1BroThoughtHeClever():
    rot1 = input("Type your text to encrypt:\n")
    shiftedROT1 = ""
    for rot1txt in rot1:
        if rot1txt >= 'a' and rot1txt <= 'z':
            shiftedROT1 += chr((ord(rot1txt) - ord('a')) + 1 + ord('a'))
        elif rot1txt >= 'A' and rot1txt <= 'Z':
            shiftedROT1 += chr((ord(rot1txt) - ord('A')) + 1 + ord('A'))
        else:
            shiftedROT1 += rot1txt
    return shiftedROT1

def morseCode():
    morseEnc = input("Type your text to encrypt:\n").upper()
    MORSE_DICT = {'A': '.-', 'B': '-...',
                       'C': '-.-.', 'D': '-..', 'E': '.',
                       'F': '..-.', 'G': '--.', 'H': '....',
                       'I': '..', 'J': '.---', 'K': '-.-',
                       'L': '.-..', 'M': '--', 'N': '-.',
                       'O': '---', 'P': '.--.', 'Q': '--.-',
                       'R': '.-.', 'S': '...', 'T': '-',
                       'U': '..-', 'V': '...-', 'W': '.--',
                       'X': '-..-', 'Y': '-.--', 'Z': '--..',
                       '1': '.----', '2': '..---', '3': '...--',
                       '4': '....-', '5': '.....', '6': '-....',
                       '7': '--...', '8': '---..', '9': '----.',
                       '0': '-----', ', ': '--..--', '.': '.-.-.-',
                       '?': '..--..', '/': '-..-.', '-': '-....-',
                       '(': '-.--.', ')': '-.--.-'}
    encryptedMorse = []
    for char in morseEnc:
        if char in MORSE_DICT:
            encryptedMorse.append(MORSE_DICT[char])
    return ' '.join(encryptedMorse)

def binaryEnc():
    my_binary = input("Type your text to encrypt:\n")
    create_bin = ""
    for b in my_binary:
        create_bin += bin(ord(b))[2:]
    return create_bin

def base64Enc():
    utf8encT = input("Type your text to encrypt:\n")
    utf8enc = utf8encT.encode('utf-8')
    base64EncJ = base64.b64encode(utf8enc)
    return base64EncJ.decode('utf-8')

def md2(message):
    s_box = [
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
        98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
        30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
        190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
        169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
        128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
        255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
        79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
        69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
        27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
        85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
        44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
        106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
        120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
        242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
        49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20
    ]

    message = bytearray(message)

    # Padding the message to a multiple of 16 bytes
    pad_len = 16 - (len(message) % 16)
    message.extend([pad_len] * pad_len)

    # Initialize variables
    state_var_arr = [0] * 48
    checksum = [0] * 16

    # Process each 16-byte block
    for i in range(0, len(message), 16):
        block = message[i:i + 16]

        # Update checksum
        temp = checksum[15]
        for j in range(16):
            checksum[j] ^= s_box[block[j] ^ temp]
            temp = checksum[j]

        # Update state X
        temp = 0
        for j in range(16):
            state_var_arr[j + 16] = block[j]
            state_var_arr[j + 32] = state_var_arr[j + 16] ^ state_var_arr[j]

        for j in range(18):
            for k in range(48):
                temp = state_var_arr[k] ^ s_box[temp]
                state_var_arr[k] = temp
            temp = (temp + j) % 256

    #Append checksum to the message
    message.extend(checksum)

    #Process the last 16-byte block (which includes the checksum)
    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        temp = 0
        for j in range(16):
            state_var_arr[j + 16] = block[j]
            state_var_arr[j + 32] = state_var_arr[j + 16] ^ state_var_arr[j]
        for j in range(18):
            for k in range(48):
                temp = state_var_arr[k] ^ s_box[temp]
                state_var_arr[k] = temp
            temp = (temp + j) % 256

    #first 16 bytes of X
    return bytes(state_var_arr[:16])

def left_rotate(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def md4() -> bytes:
    md41 = input("Type your text to encrypt:\n").encode('utf-8')
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (~x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    #Padding
    orig_len = len(md41)
    md41 += b'\x80' # Adding 1 bit
    while(len(md41) % 64) != 56:
        md41 += b'\x00' #Adding 0's that can be divide by 512 bit(64 bytes)

    #Adding message length in bits(64 bit number, fisrt byte is smallest)
    md41 += struct.pack('<Q', orig_len * 8)

    #Dividing message in blocks by 512 bits
    for i in range(0, len(md41), 64):
        block = md41[i:i+64]
        X = struct.unpack('<16I', block) #Dividing block by 16 32words' bit

        #Saving current state
        AA, BB, CC, DD = A, B, C, D

        #First round
        A = left_rotate((A + F(B, C, D) + X[0]), 3)
        D = left_rotate((D + F(B, C, D) + X[1]), 7)
        C = left_rotate((C + F(B, C, D) + X[2]), 11)
        B = left_rotate((B + F(B, C, D) + X[3]), 19)

        A = left_rotate((A + F(B, C, D) + X[4]), 3)
        D = left_rotate((D + F(A, B, C) + X[5]), 7)
        C = left_rotate((C + F(D, A, B) + X[6]), 11)
        B = left_rotate((B + F(C, D, A) + X[7]), 19)

        A = left_rotate((A + F(B, C, D) + X[8]), 3)
        D = left_rotate((D + F(A, B, C) + X[9]), 7)
        C = left_rotate((C + F(D, A, B) + X[10]), 11)
        B = left_rotate((B + F(C, D, A) + X[11]), 19)

        A = left_rotate((A + F(B, C, D) + X[12]), 3)
        D = left_rotate((D + F(A, B, C) + X[13]), 7)
        C = left_rotate((C + F(D, A, B) + X[14]), 11)
        B = left_rotate((B + F(C, D, A) + X[15]), 19)

        #Second round
        A = left_rotate((A + G(B, C, D) + X[0] + 0x5A827999), 3)
        D = left_rotate((D + G(A, B, C) + X[4] + 0x5A827999), 5)
        C = left_rotate((C + G(D, A, B) + X[8] + 0x5A827999), 9)
        B = left_rotate((B + G(C, D, A) + X[12] + 0x5A827999), 13)

        A = left_rotate((A + G(B, C, D) + X[1] + 0x5A827999), 3)
        D = left_rotate((D + G(A, B, C) + X[5] + 0x5A827999), 5)
        C = left_rotate((C + G(D, A, B) + X[9] + 0x5A827999), 9)
        B = left_rotate((B + G(C, D, A) + X[13] + 0x5A827999), 13)

        A = left_rotate((A + G(B, C, D) + X[2] + 0x5A827999), 3)
        D = left_rotate((D + G(A, B, C) + X[6] + 0x5A827999), 5)
        C = left_rotate((C + G(D, A, B) + X[10] + 0x5A827999), 9)
        B = left_rotate((B + G(C, D, A) + X[14] + 0x5A827999), 13)

        A = left_rotate((A + G(B, C, D) + X[3] + 0x5A827999), 3)
        D = left_rotate((D + G(A, B, C) + X[7] + 0x5A827999), 5)
        C = left_rotate((C + G(D, A, B) + X[11] + 0x5A827999), 9)
        B = left_rotate((B + G(C, D, A) + X[15] + 0x5A827999), 13)

        #Third round
        A = left_rotate((A + H(B, C, D) + X[0] + 0x6ED9EBA1), 3)
        D = left_rotate((D + H(A, B, C) + X[8] + 0x6ED9EBA1), 9)
        C = left_rotate((C + H(D, A, B) + X[4] + 0x6ED9EBA1), 11)
        B = left_rotate((B + H(C, D, A) + X[12] + 0x6ED9EBA1), 15)

        A = left_rotate((A + H(B, C, D) + X[2] + 0x6ED9EBA1), 3)
        D = left_rotate((D + H(A, B, C) + X[10] + 0x6ED9EBA1), 9)
        C = left_rotate((C + H(D, A, B) + X[6] + 0x6ED9EBA1), 11)
        B = left_rotate((B + H(C, D, A) + X[14] + 0x6ED9EBA1), 15)

        A = left_rotate((A + H(B, C, D) + X[1] + 0x6ED9EBA1), 3)
        D = left_rotate((D + H(A, B, C) + X[9] + 0x6ED9EBA1), 9)
        C = left_rotate((C + H(D, A, B) + X[5] + 0x6ED9EBA1), 11)
        B = left_rotate((B + H(C, D, A) + X[13] + 0x6ED9EBA1), 15)

        A = left_rotate((A + H(B, C, D) + X[3] + 0x6ED9EBA1), 3)
        D = left_rotate((D + H(A, B, C) + X[11] + 0x6ED9EBA1), 9)
        C = left_rotate((C + H(D, A, B) + X[7] + 0x6ED9EBA1), 11)
        B = left_rotate((B + H(C, D, A) + X[15] + 0x6ED9EBA1), 15)

        #Adding value to the initial state
        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    #Returning result hash in 16 byte (128 bit) state
    return struct.pack('<4I', A, B, C, D)

def rail_fence():
    arr = []
    ind = 0
    dir = 1
    res = ""
    rf = ""
    rfIn = input("Type your text: ").upper()
    rfCreateArrayCol = input("How many columns you would like to use? ")
    if not rfCreateArrayCol.isdigit():
        print("Input must be a whole number.")
        return
    else:
        rfCreateArrayCol = int(rfCreateArrayCol)  # Преобразуем строку в целое число
        if rfCreateArrayCol > len(rfIn):
            print("Number of columns must be not greater than the length of the word itself.")
            return

        for _ in range(rfCreateArrayCol):
            arr.append([])
        for i in rfIn:
            arr[ind].append(i)
            ind += dir
            if ind == 0:
                dir = 1
            elif ind == rfCreateArrayCol - 1:
                dir = -1
        for j in arr:
            res += ''.join(j)
    return res

def trans():
    transpositionAskTxt = input("Type your text to encrypt: ")
    transpositionAskKey = input("Please enter key: ")
    rows = len(transpositionAskKey)
    cols = [''] * rows
    for index, symbol in enumerate(transpositionAskTxt):
        colIndex = index % rows
        cols[colIndex] += symbol
    res = ''.join(cols)
    return res

if __name__ == "__main__":
    main()
