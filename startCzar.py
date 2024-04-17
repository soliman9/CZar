import os
import platform
import ctypes
from hashlib import sha256
import argparse
import logging
from cryptography.exceptions import InvalidTag
<<<<<<< HEAD
from ioUtils.readFromShell import (
    readChoice,
    readPassId,
    readUserName,
    readPassword,
    readMode,
)
from crypto.aes import encrypt, decrypt, generateSalt, generateKey
from ioUtils.clipboardUtils import copyToClipboard
from ioUtils.ioUtilities import (
    readfromFile,
    writetoFile,
    deleteFile,
    appendToTextFile,
    readfromTextFile,
)
=======
from ioUtils.readFromShell import \
    readChoice, readPassId, readUserName, readPassword, readMode
from crypto.aes import encrypt, decrypt, generateSalt, generateKey
from ioUtils.clipboardUtils import copyToClipboard
from ioUtils.ioUtilities import readfromFile, writetoFile, deleteFile, \
    appendToTextFile, readfromTextFile
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
from crypto.randomPwd import generatePassword


argParser = argparse.ArgumentParser(description="CZar Password manager CLI startup")
argParser.add_argument(
<<<<<<< HEAD
    "-m",
    "--mode",
    type=str,
    dest="cZarMode",
    help="CZar startup mode; set (s): to create new password; \
        get (g): to retrieve password; del (d): to delete a password",
    default="",
=======
    '-m', '--mode', type=str,
    dest='cZarMode',
    help='CZar startup mode; set (s): to create new password; \
        get (g): to retrieve password; del (d): to delete a password',
    default=''
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
)
# Get arguments from user through CLI
args = argParser.parse_args()


class CZar:
    def __init__(self, args):
        try:
            os.mkdir("Czar_logs")
        except FileExistsError:
            pass
        logging.basicConfig(
            filename="Czar_logs/czar.log",
            format="%(levelname)s | %(asctime)s | %(message)s",
            datefmt="%m/%d/%Y %H:%M",
            level=logging.ERROR,
        )
        self.cZarMode = args.cZarMode.lower()
        # Init master key
<<<<<<< HEAD
        self.mPassword = readPassword("Master")
=======
        self.mPassword = readPassword('Master')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c

        # Create data directory
        self.currentOS = platform.system()
        try:
            if self.currentOS == "Windows":
                os.mkdir("data")
                ctypes.windll.kernel32.SetFileAttributesW("data", 0x02)
            elif self.currentOS == "Linux":
                os.mkdir(".data")
        except FileExistsError:
            pass  # Directory already exists
        # generating master key
<<<<<<< HEAD
        mSaltFileName = sha256(self.mPassword.encode("utf-8")).hexdigest()
=======
        mSaltFileName = sha256(self.mPassword.encode('utf-8')).hexdigest()
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        try:
            mSalt = readfromFile(mSaltFileName, self.currentOS)
        except FileNotFoundError:
            mSalt = generateSalt()
            writetoFile(mSalt, mSaltFileName, self.currentOS)
<<<<<<< HEAD
        self.mKey = generateKey(mSalt, self.mPassword.encode("utf-8"))
=======
        self.mKey = generateKey(mSalt, self.mPassword.encode('utf-8'))
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c

    def displayPassIds(self):
        # Display list pf IDs.
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(passIdFile, self.currentOS)
<<<<<<< HEAD
        print("Here's a list of saved password IDs")
        pList = ""
        for i in range(len(passIdList)):
            if (i % 5) == 0:
                pList += "\n"
            pList += passIdList[i] + " " * 4
=======
        print('Here\'s a list of saved password IDs')
        pList = ''
        for i in range(len(passIdList)):
            if (i % 5) == 0:
                pList += '\n'
            pList += (passIdList[i] + ' '*4)
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        print(pList)

    def savePassId(self, passId):
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(passIdFile, self.currentOS)
        if passId in passIdList:
            return False
        else:
            appendToTextFile(passId, passIdFile, self.currentOS)
            return True

    def removePassId(self, passId):
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(passIdFile, self.currentOS)
        if passId in passIdList:
            passIdList.remove(passId)
            # Delete PassID File and Create a new one.
            deleteFile(passIdFile, self.currentOS)
            for pId in passIdList:
                if len(pId) != 0:
                    appendToTextFile(pId, passIdFile, self.currentOS)

    def savePassword(self):
        self.displayPassIds()
<<<<<<< HEAD
        print("=== Set/Update Password ===")
=======
        print('=== Set/Update Password ===')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        # password ID must be unique
        passId = readPassId()
        updatePassword = False
        while not self.savePassId(passId):
<<<<<<< HEAD
            print("This Password ID exists.")
            if readChoice(f'Do you want to update the password of "{passId}"?') == "y":
=======
            print('This Password ID exists.')
            if readChoice(
                 f'Do you want to update the password of \"{passId}\"?') == 'y':
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
                updatePassword = True
                break
            else:
                passId = readPassId()
        usrName = readUserName(passId)

        # Ask user if he wants to get new password
<<<<<<< HEAD
        if (
            readChoice("Do you want Czar to choose" " a new secure password for you?")
            == "y"
        ):
            password = generatePassword().encode("utf-8")
=======
        if readChoice('Do you want Czar to choose'
                      ' a new secure password for you?') == 'y':
            password = generatePassword().encode('utf-8')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        else:
            Password_1 = readPassword(passId).encode("utf-8")
            print("Please, re-enter your password")
            password_2 = readPassword(passId).encode("utf-8")
            if password_2 != Password_1:
                print("Error: Passwords don't match ..")
                return
            password = password_2

<<<<<<< HEAD
        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        usrAad = passId.encode("utf-8")
        encUsrName, key, nonce = encrypt(
            usrName.encode("utf-8"), usrAad, key=self.mKey, nonce=baseNonce
=======
        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        usrAad = passId.encode('utf-8')
        encUsrName, key, nonce = encrypt(
            usrName.encode('utf-8'), usrAad,
            key=self.mKey, nonce=baseNonce
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        )

        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        passNonceString = passIdHash + self.mPassword
        passNonce = (
            sha256(passNonceString.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        )

        passAad = (passId + usrName).encode("utf-8")
        encPassword, passKey, nonce = encrypt(
            password, passAad, key=self.mKey, nonce=passNonce
        )

        # write data to files
        aadHash = sha256(passAad).hexdigest()
        if updatePassword:
            try:
                deleteFile(passIdHash, self.currentOS)
            except FileNotFoundError:
<<<<<<< HEAD
                logging.error("File I/O Error")
                print("Error: Try again!")
=======
                logging.error('File I/O Error')
                print('Error: Try again!')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
                return
            try:
                deleteFile(aadHash, self.currentOS)
            except FileNotFoundError:
                pass  # Username updated
        writetoFile(encUsrName, passIdHash, self.currentOS)
        writetoFile(encPassword, aadHash, self.currentOS)
        print("\nPassword saved successfully!\n")

    def getPassword(self):
        self.displayPassIds()
<<<<<<< HEAD
        print("=== Get Password ===")
=======
        print('=== Get Password ===')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        # Retrieving password
        passId = readPassId()
        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash, self.currentOS)
        except FileNotFoundError:
            logging.error("Incorrect Password ID.")
            print("Error: Incorrect Input.")
            return

        # Decrypting username
<<<<<<< HEAD
        usrAad = passId.encode("utf-8")
        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, baseNonce).decode("utf-8")
=======
        usrAad = passId.encode('utf-8')
        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        try:
            usrName = decrypt(
                self.mKey, encUsrName, usrAad, baseNonce).decode('utf-8')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        except InvalidTag:
            print("Error: Incorrect Input.")
            return

        # decrypting password
        passAad = (passId + usrName).encode("utf-8")
        aadHash = sha256(passAad).hexdigest()
        # Read Encrypted password
        try:
            encPassword = readfromFile(aadHash, self.currentOS)
        except FileNotFoundError:
            logging.error("Cannot read password file {}".format(aadHash))
            print("Error: Something went wrong. Try again!")
            return

        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        passNonceString = passIdHash + self.mPassword
        passNonce = (
            sha256(passNonceString.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        )

        password = decrypt(self.mKey, encPassword, passAad, passNonce)
        copyToClipboard(password.decode("utf-8"))
        print("Your account username is: {}".format(usrName))
        print("\nPassword copied successfully!\n")

    def deletePassword(self):
        self.displayPassIds()
<<<<<<< HEAD
        print("=== Delete Password ===")
        passId = readPassId()
        if readChoice(f"Are you sure you want to delete '{passId}'?") == "n":
            return
        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
=======
        print('=== Delete Password ===')
        passId = readPassId()
        if readChoice(f'Are you sure you want to delete \'{passId}\'?') == 'n':
            return
        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        try:
            encUsrName = readfromFile(passIdHash, self.currentOS)
            deleteFile(passIdHash, self.currentOS)
        except FileNotFoundError:
            logging.error("Incorrect Password ID.")
            print("Error: Incorrect Input.")
            return
        # Decrypting username
<<<<<<< HEAD
        usrAad = passId.encode("utf-8")
        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, baseNonce).decode("utf-8")
=======
        usrAad = passId.encode('utf-8')
        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        try:
            usrName = decrypt(
                self.mKey, encUsrName, usrAad, baseNonce).decode('utf-8')
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
        except InvalidTag:
            print("Error: Incorrect Input.")
            return

        passAad = (passId + usrName).encode("utf-8")
        aadHash = sha256(passAad).hexdigest()

        # Delete password file
        try:
            deleteFile(aadHash, self.currentOS)
            self.removePassId(passId)
        except FileNotFoundError:
            logging.error("Cannot find password file {}".format(aadHash))
            print("Error: Something went wrong. Try again!")
            return
        print("\nPassword Deleted successfully!\n")

    def start(self):
        stillRunning = True
        if self.cZarMode:
            mode = self.cZarMode
        else:
            mode = readMode()

        while stillRunning:
<<<<<<< HEAD
            if mode == "set" or mode == "s":
=======
            if mode == 'set' or mode == 's':
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
                self.savePassword()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
<<<<<<< HEAD
            elif mode == "get" or mode == "g":
=======
            elif mode == 'get' or mode == 'g':
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
                self.getPassword()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
<<<<<<< HEAD
            elif mode == "del" or mode == "d":
=======
            elif mode == 'del' or mode == 'd':
>>>>>>> 4021a9f42a5c86a0666388a8e4916d24373caa6c
                self.deletePassword()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
            else:
                logging.error("Undefined input mode!")
                print("Undefined input mode!")
                stillRunning = False

        # Clear clipboard before shutting down CZar
        copyToClipboard("")
        logging.info("Shutting down CZar ...")
        print("\nShutting down CZar ...")


def main(args):
    try:
        cZar = CZar(args)
        # Start Czar
        cZar.start()
    except KeyboardInterrupt:
        copyToClipboard("")
        logging.info("Shutting down CZar ...")
        print("\nShutting down CZar ...")


if __name__ == "__main__":
    main(args)
