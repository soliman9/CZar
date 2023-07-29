import os
import platform
import ctypes
from hashlib import sha256
import argparse
import logging
from cryptography.exceptions import InvalidTag
from ioUtils.readFromShell import \
    readChoice, readPassId, readUserName, readPassword, readMode
from crypto.aes import encrypt, decrypt
from ioUtils.clipboardUtils import copyToClipboard
from ioUtils.ioUtilities import readfromFile, writetoFile, deleteFile
from crypto.randomPwd import generatePassword


argParser = argparse.ArgumentParser(
    description='CZar Password manager CLI startup')
argParser.add_argument(
    '-m', '--mode', type=str,
    dest='cZarMode',
    help='CZar startup mode; set: to create new password; \
        get: to retrieve password; del: to delete a password',
    default=''
)
# Get arguments from user through CLI
args = argParser.parse_args()


class CZar():
    def __init__(self, args):
        try:
            os.mkdir('Czar_logs')
        except FileExistsError:
            pass
        logging.basicConfig(
            filename='Czar_logs/czar.log',
            format='%(levelname)s | %(asctime)s | %(message)s',
            datefmt='%m/%d/%Y %H:%M',
            level=logging.ERROR
        )
        self.cZarMode = args.cZarMode.lower()
        # Init master key
        self.mPassword = readPassword('Master')
        self.mKey = sha256(self.mPassword.encode('utf-8')).digest()
        # Create data directory
        self.currentOS = platform.system()
        try:
            if self.currentOS == 'Windows':
                os.mkdir('data')
                ctypes.windll.kernel32.SetFileAttributesW('data', 0x02)
            elif self.currentOS == 'Linux':
                os.mkdir('.data')
        except FileExistsError:
            pass  # Directory already exists

    def savePassword(self):
        # password ID must be unique
        passId = readPassId()
        usrName = readUserName(passId)

        # Ask user if he wants to get new password
        if readChoice('Do you want Czar to choose'
                      ' a new secure password for you?') == 'y':
            password = generatePassword().encode('utf-8')
        else:
            Password_1 = readPassword(passId).encode('utf-8')
            print('Please, re-enter your password')
            password_2 = readPassword(passId).encode('utf-8')
            if password_2 != Password_1:
                print('Error: Passwords don\'t match ..')
                return
            password = password_2

        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        usrAad = passId.encode('utf-8')
        encUsrName, key, nonce = encrypt(
            usrName.encode('utf-8'), usrAad,
            key=self.mKey, nonce=baseNonce
        )

        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        passNonceString = passIdHash + self.mPassword
        passNonce = sha256(passNonceString.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')

        passAad = (passId + usrName).encode('utf-8')
        encPassword, passKey, nonce = encrypt(
            password, passAad, key=self.mKey, nonce=passNonce
        )

        # write data to files
        aadHash = sha256(passAad).hexdigest()
        writetoFile(encUsrName, passIdHash, self.currentOS)
        writetoFile(encPassword, aadHash, self.currentOS)
        print('\nPassword saved successfully!\n')

    def getPassword(self):
        # Retrieving password
        passId = readPassId()
        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash, self.currentOS)
        except FileNotFoundError:
            logging.error('Incorrect Password ID.')
            print('Error: Incorrect Input.')
            return

        # Decrypting username
        usrAad = passId.encode('utf-8')
        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        try:
            usrName = decrypt(
                self.mKey, encUsrName, usrAad, baseNonce).decode('utf-8')
        except InvalidTag:
            print('Error: Incorrect Input.')
            return

        # decrypting password
        passAad = (passId + usrName).encode('utf-8')
        aadHash = sha256(passAad).hexdigest()
        # Read Encrypted password
        try:
            encPassword = readfromFile(aadHash, self.currentOS)
        except FileNotFoundError:
            logging.error('Cannot read password file {}'.format(
                aadHash)
            )
            print('Error: Something went wrong. Try again!')
            return

        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        passNonceString = passIdHash + self.mPassword
        passNonce = sha256(passNonceString.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')

        password = decrypt(self.mKey, encPassword, passAad, passNonce)
        copyToClipboard(password.decode('utf-8'))
        print('Your account username is: {}'.format(usrName))
        print('\nPassword copied successfully!\n')

    def deletePassword(self):
        passId = readPassId()
        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash, self.currentOS)
            deleteFile(passIdHash, self.currentOS)
        except FileNotFoundError:
            logging.error('Incorrect Password ID.')
            print('Error: Incorrect Input.')
            return
        # Decrypting username
        usrAad = passId.encode('utf-8')
        baseNonce = sha256(passId.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')
        try:
            usrName = decrypt(
                self.mKey, encUsrName, usrAad, baseNonce).decode('utf-8')
        except InvalidTag:
            print('Error: Incorrect Input.')
            return

        passAad = (passId + usrName).encode('utf-8')
        aadHash = sha256(passAad).hexdigest()

        # Delete password file
        try:
            deleteFile(aadHash, self.currentOS)
        except FileNotFoundError:
            logging.error('Cannot find password file {}'.format(
                aadHash)
            )
            print('Error: Something went wrong. Try again!')
            return
        print('\nPassword Deleted successfully!\n')

    def start(self):
        stillRunning = True
        if self.cZarMode:
            mode = self.cZarMode
        else:
            mode = readMode()

        while stillRunning:
            if mode == 'set':
                self.savePassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            elif mode == 'get':
                self.getPassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            elif mode == 'del':
                self.deletePassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            else:
                logging.error('Undefined input mode!')
                print('Undefined input mode!')
                stillRunning = False

        # Clear clipboard before shutting down CZar
        copyToClipboard('')
        logging.info('Shutting down CZar ...')
        print('\nShutting down CZar ...')


def main(args):
    try:
        cZar = CZar(args)
        # Start Czar
        cZar.start()
    except KeyboardInterrupt:
        copyToClipboard('')
        logging.info('Shutting down CZar ...')
        print('\nShutting down CZar ...')


if __name__ == "__main__":
    main(args)
