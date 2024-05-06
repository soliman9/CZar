import os
from time import time
import threading
import datetime
import shutil
import platform
import ctypes
from hashlib import sha256
import argparse
import logging
from cryptography.exceptions import InvalidTag
from tabulate import tabulate
from more_itertools import chunked_even
from ioUtils.readFromShell import (
    readChoice,
    readPassId,
    readUserName,
    readPassword,
    readMode,
)
from crypto.aes import encrypt, decrypt, generateSalt, generateKey
from ioUtils.clipboardUtils import copyToClipboard, clearClipboard
from ioUtils.ioUtilities import (
    readfromFile,
    writetoFile,
    deleteFile,
    appendToTextFile,
    readfromTextFile,
)
from crypto.randomPwd import generatePassword


argParser = argparse.ArgumentParser(description="CZar Password manager CLI startup")
argParser.add_argument(
    "-m",
    "--mode",
    type=str,
    dest="cZarMode",
    help="CZar startup mode; set (s): to create new password; \
        get (g): to retrieve password; del (d): to delete a password; \
        export (e): to export a backup compressed file.",
    default="",
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
        self.mPassword = readPassword("Master")

        # Create data directory
        self.dataDir = None
        self.currentOS = platform.system()
        try:
            if self.currentOS == "Windows":
                self.dataDir = "data"
                os.mkdir("data")
                ctypes.windll.kernel32.SetFileAttributesW("data", 0x02)
            elif self.currentOS == "Linux":
                self.dataDir = ".data"
                os.mkdir(".data")
        except FileExistsError:
            pass  # Directory already exists
        # generating master key
        mSaltFileName = sha256(self.mPassword.encode("utf-8")).hexdigest()
        try:
            mSalt = readfromFile(mSaltFileName, self.currentOS)
        except FileNotFoundError:
            mSalt = generateSalt()
            writetoFile(mSalt, mSaltFileName, self.currentOS)
        self.mKey = generateKey(mSalt, self.mPassword.encode("utf-8"))
        self.timerThread = None

    def clipboardTimer(self):
        start_time = time()
        while time() - start_time < 60:
            pass
        clearClipboard()

    def displayPassIds(self):
        # Display list pf IDs.
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(passIdFile, self.currentOS)
        print("Here are lists of saved password IDs")
        passIdRows = list(chunked_even(passIdList, 5))
        headers = [f"List {i + 1}" for i in range(5)]
        print(tabulate(passIdRows, headers=headers, tablefmt="grid"))


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
        print("=== Set/Update Password ===")
        # password ID must be unique
        passId = readPassId()
        updatePassword = False
        while not self.savePassId(passId):
            print("This Password ID exists.")
            if readChoice(f"Do you want to update the password of '{passId}'?") == "y":
                updatePassword = True
                break
            else:
                passId = readPassId()
        usrName = readUserName(passId)

        # Ask user if he wants to get new password
        if (
            readChoice("Do you want Czar to choose a new secure password for you?")
            == "y"
        ):
            password = generatePassword().encode("utf-8")
        else:
            Password_1 = readPassword(passId).encode("utf-8")
            print("Please, re-enter your password")
            password_2 = readPassword(passId).encode("utf-8")
            if password_2 != Password_1:
                print("Error: Passwords don't match ..")
                return
            password = password_2

        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        usrAad = passId.encode("utf-8")
        encUsrName, key, nonce = encrypt(
            usrName.encode("utf-8"), usrAad, key=self.mKey, nonce=baseNonce
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
                logging.error("File I/O Error")
                print("Error: Try again!")
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
        print("=== Get Password ===")
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
        usrAad = passId.encode("utf-8")
        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, baseNonce).decode("utf-8")
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
        print("=== Delete Password ===")
        passId = readPassId()
        if readChoice(f"Are you sure you want to delete '{passId}'?") == "n":
            return
        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        try:
            encUsrName = readfromFile(passIdHash, self.currentOS)
            deleteFile(passIdHash, self.currentOS)
        except FileNotFoundError:
            logging.error("Incorrect Password ID.")
            print("Error: Incorrect Input.")
            return
        # Decrypting username
        usrAad = passId.encode("utf-8")
        baseNonce = sha256(passId.encode("utf-8")).hexdigest()[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad, baseNonce).decode("utf-8")
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
            logging.error(f"Cannot find password file {aadHash}")
            print("Error: Something went wrong. Try again!")
            return
        print("\nPassword Deleted successfully!\n")


    def exportData(self):
        currentDateTime = str(datetime.datetime.now()).split(".")[0].replace(":", "").replace(" ", "-")
        try:
            if self.currentOS == "Windows":
                shutil.make_archive(currentDateTime, "zip", self.dataDir)
                return currentDateTime + ".zip"
            elif self.currentOS == "Linux":
                shutil.make_archive(currentDateTime, "gztar", self.dataDir)
                return currentDateTime + ".tar.gz"
            else:
                return None
        except Exception:
            return None
        return None

    def start(self):
        stillRunning = True
        if self.cZarMode:
            mode = self.cZarMode
        else:
            mode = readMode()

        while stillRunning:
            if mode in ("set", "s"):
                self.savePassword()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
            elif mode in ("get", "g"):
                self.getPassword()
                self.timerThread = threading.Thread(target=self.clipboardTimer)
                self.timerThread.start()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
            elif mode in ("del", "d"):
                self.deletePassword()
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
                else:
                    mode = readMode()
            elif mode in ("export", "e"):
                if readChoice("All encrypted files will be exported to current directory. Continue?") == "y":
                    fileName = self.exportData()
                    if fileName is not None:
                        print(f"***Successful backup saved to: {fileName}")
                        print("***You should save this file on another secured device.")
                    else:
                        print("Error: Unable to save a new backup file")
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
                else:
                    mode = readMode()
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
