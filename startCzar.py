from ioUtils.readFromShell import *
from crypto.aes import encrypt, decrypt
from ioUtils.clipboardUtils import copyToClipboard
from ioUtils.ioUtilities import readfromFile, writetoFile, deleteFile
from hashlib import sha256
import argparse
import logging
from cryptography.exceptions import InvalidTag


parser = argparse.ArgumentParser(
    description='CZar Password manager CLI startup')
parser.add_argument(
    '-m', '--mode', type=str,
    dest='cZarMode',
    help='CZar startup mode; \nset: to create new password; \nget: to retrieve password',
    default='get'
)
# Collect arguments from user through cli
args = parser.parse_args()


class CZar():
    def __init__(self, args):
        logging.basicConfig(
            filename='data/logs/czar.log',
            format='%(levelname)s | %(asctime)s | %(message)s',
            datefmt='%m/%d/%Y %H:%M',
            level=logging.INFO
        )
        self.cZarMode = args.cZarMode.lower()
        # Init master key
        self.mPassword = readPassword('Master')
        self.mKey = sha256(self.mPassword.encode('utf-8')).digest()
        baseNonceString = '0000' + self.mPassword
        self.baseNonce = sha256(baseNonceString.encode(
            'utf-8')).hexdigest()[:24].encode('utf-8')

    def savePassword(self):
        # password ID must be unique
        passId = readPassId()
        usrName = readUserName(passId)
        password = readPassword(passId).encode('utf-8')

        usrAad = passId.encode('utf-8')
        encUsrName, key, nonce = encrypt(
            usrName.encode('utf-8'), usrAad,
            key=self.mKey, nonce=self.baseNonce
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
        writetoFile(encUsrName, passIdHash)
        writetoFile(encPassword, aadHash)
        print('\nPassword saved successfully!\n')

    def getPassword(self):
        # Retrieving password
        passId = readPassId()
        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash)
        except FileNotFoundError:
            logging.error('Incorrect Password ID.')
            print('Error: Incorrect Input.')
            return

        # Decrypting username
        usrAad = passId.encode('utf-8')

        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, self.baseNonce).decode('utf-8')
        except InvalidTag:
            print('Error: Incorrect Input.')
            return

        # decrypting password
        passAad = (passId + usrName).encode('utf-8')
        aadHash = sha256(passAad).hexdigest()
        # Read Encrypted password
        try:
            encPassword = readfromFile(aadHash)
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
        print('\nPassword copied successfully!\n')

    def deletePassword(self):
        passId = readPassId()
        passIdHash = sha256(passId.encode('utf-8')).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash)
            deleteFile(passIdHash)
        except FileNotFoundError:
            logging.error('Incorrect Password ID.')
            print('Error: Incorrect Input.')
            return
        # Decrypting username
        usrAad = passId.encode('utf-8')
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, self.baseNonce).decode('utf-8')
        except InvalidTag:
            print('Error: Incorrect Input.')
            return

        passAad = (passId + usrName).encode('utf-8')
        aadHash = sha256(passAad).hexdigest()

        # Delete password file
        try:
            deleteFile(aadHash)
        except FileNotFoundError:
            logging.error('Cannot find password file {}'.format(
                aadHash)
            )
            print('Error: Something went wrong. Try again!')
            return
        print('\nPassword Deleted successfully!\n')

    def start(self):
        stillRunning = True
        while stillRunning:
            if self.cZarMode == 'set':
                self.savePassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            elif self.cZarMode == 'get':
                self.getPassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            elif self.cZarMode == 'del':
                self.deletePassword()
                if readChoice('Do you want to continue using CZar?') == 'n':
                    stillRunning = False
            else:
                logging.error('Undefined input mode!')
                print('Undefined input mode!')
                if readChoice('Do you want to continue using CZar?') == 'n':
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
