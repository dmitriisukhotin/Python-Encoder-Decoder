import re

def main():
    userPrompt()

def userPrompt():
    whatToDo = input("Do you want to Encrypt or Decrypt?(Type enc for Encryption and dec for decryption)\n")
    if whatToDo == "dec":
        whichOne = input("Which decryption method do you want to use? Type one of the following: \n1. Ceasar\n2. Vigenère Cipher\n3. ROT13\n4. Atbash Cipher"
                         "\n5. XOR")
    elif whatToDo == "enc":
        whichOne1 = input("Type a string/key/or text to encrypt")
    else:
        print("Invalid command.")
    
    return whatToDo

#def notaeCaesarianaeDec():

#def notaeCaesarianaeEnc():

if __name__ == "__main__":
    main()
