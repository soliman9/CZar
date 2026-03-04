import os
from time import time, sleep
import threading
import datetime
import shutil
import platform
import ctypes
from hashlib import sha256, pbkdf2_hmac
from argon2 import PasswordHasher
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
    readBackupFileName,
    readUsername,
    readAuthChoice,
)
from userManagement import UserManager
from crypto.aes import encrypt, decrypt, generateKey
from ioUtils.clipboardUtils import copyToClipboard, clearClipboard
from ioUtils.ioUtilities import (
    readfromFile,
    writetoFile,
    deleteFile,
    appendToTextFile,
    readfromTextFile,
)
from crypto.randomPwd import generatePassword


argParser = argparse.ArgumentParser(
    description="CZar Password manager CLI startup")
argParser.add_argument(
    "-m",
    "--mode",
    type=str,
    dest="cZarMode",
    help="CZar startup mode; set (s): to create new password; \
        get (g): to retrieve password; del (d): to delete a password; \
        export (e): to export a backup compressed file;\
        import (i): to import passwords from a backup compressed file.",
    default="",
)
# Get arguments from user through CLI
args = argParser.parse_args()


def authenticate_user(currentOS):
    """Handle user authentication and registration using master password."""
    user_manager = UserManager(currentOS)

    print("\n=== CZar Password Manager ===")
    choice = readAuthChoice()

    while True:
        username = readUsername()
        # Use master password for both authentication and encryption
        master_password = readPassword("Master")

        if choice == 'l':  # Login
            success, message = user_manager.authenticate_user(
                username, master_password)
            if success:
                print(f"Welcome back, {username}!")
                return username, user_manager, master_password
            else:
                print(f"Error: {message}")
                choice = readAuthChoice()
        else:  # Create account
            confirm_pwd = readPassword("Master (confirm)")
            if master_password != confirm_pwd:
                print("Error: Passwords don't match")
                choice = readAuthChoice()
                continue

            success, message = user_manager.create_user(
                username, master_password)
            if success:
                print(f"Account created successfully! Welcome, {username}!")
                return username, user_manager, master_password
            else:
                print(f"Error: {message}")
                choice = readAuthChoice()


class CZar:
    def __init__(self, cliArgs, username, master_password):
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
        self.username = username
        self.cZarMode = cliArgs.cZarMode.lower()
        # Use master password from authentication
        self.mPassword = master_password

        # Create data directory
        self.dataDir = None
        self.currentOS = platform.system()
        self.makeDataDirectory()
        # Initialize password hasher for password IDs
        self.ph = PasswordHasher()
        # Generate master key from password using PBKDF2
        # for secure key derivation with username as salt
        mSalt = pbkdf2_hmac(
            "sha256",
            self.mPassword.encode("utf-8"),
            self.username.encode("utf-8"),
            480000
        )
        self.mKey = generateKey(mSalt, self.mPassword.encode("utf-8"))
        self.timerThread = None

    def makeDataDirectory(self):
        try:
            if self.currentOS == "Windows":
                self.dataDir = f"data/{self.username}"
                os.makedirs(self.dataDir, exist_ok=True)
                ctypes.windll.kernel32.SetFileAttributesW(self.dataDir, 0x02)
            elif self.currentOS == "Linux":
                self.dataDir = f".data/{self.username}"
                os.makedirs(self.dataDir, exist_ok=True)
        except OSError as e:
            logging.error("Failed to create data directory: %s", str(e))

    def clipboardTimer(self):
        start_time = time()
        while time() - start_time < 60:
            sleep(1)
        clearClipboard()

    def displayPassIds(self):
        # Display list pf IDs.
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(
            passIdFile, self.currentOS, self.username)
        passIdList.sort()
        print("Here are lists of saved password IDs")
        passIdRows = list(chunked_even(passIdList, 5))
        headers = [f"List {i + 1}" for i in range(5)]
        print(tabulate(passIdRows, headers=headers, tablefmt="grid"))

    def savePassId(self, passId):
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(
            passIdFile, self.currentOS, self.username)
        if passId in passIdList:
            return False
        else:
            appendToTextFile(passId, passIdFile, self.currentOS, self.username)
            return True

    def removePassId(self, passId):
        passIdFile = sha256(self.mKey).hexdigest()
        passIdList = readfromTextFile(
            passIdFile, self.currentOS, self.username)
        if passId in passIdList:
            passIdList.remove(passId)
            # Delete PassID File and Create a new one.
            deleteFile(passIdFile, self.currentOS, self.username)
            for pId in passIdList:
                if len(pId) != 0:
                    appendToTextFile(
                        pId, passIdFile, self.currentOS, self.username)

    def savePassword(self):
        self.displayPassIds()
        print("=== Set/Update Password ===")
        # password ID must be unique
        passId = readPassId()
        updatePassword = False
        while not self.savePassId(passId):
            print("This Password ID exists.")
            msg = f"Do you want to update the password of '{passId}'?"
            if readChoice(msg) == "y":
                updatePassword = True
                break
            else:
                passId = readPassId()
        usrName = readUserName(passId)

        # Ask user if he wants to get new password
        if (
            readChoice(
                "Do you want Czar to choose a new secure password for you?")
            == "y"
        ):
            password = generatePassword().encode("utf-8")
        else:
            password_1 = readPassword(passId).encode("utf-8")
            print("Please, re-enter your password")
            password_2 = readPassword(passId).encode("utf-8")
            if password_2 != password_1:
                print("Error: Passwords don't match ..")
                return
            password = password_2

        baseNonce = sha256(passId.encode("utf-8")
                           ).hexdigest()[:24].encode("utf-8")
        usrAad = passId.encode("utf-8")
        encUsrName, _, _ = encrypt(
            usrName.encode("utf-8"), usrAad, key=self.mKey, nonce=baseNonce
        )

        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        # Use PBKDF2 to derive nonce from password securely
        passNonce = pbkdf2_hmac(
            "sha256",
            self.mPassword.encode("utf-8"),
            passIdHash.encode("utf-8"),
            480000
        )[:12]

        passAad = (passId + usrName).encode("utf-8")
        encPassword, _, _ = encrypt(
            password, passAad, key=self.mKey, nonce=passNonce
        )

        # write data to files
        aadHash = sha256(passAad).hexdigest()
        if updatePassword:
            try:
                deleteFile(passIdHash, self.currentOS, self.username)
            except FileNotFoundError:
                logging.error("File I/O Error")
                print("Error: Try again!")
                return
            try:
                deleteFile(aadHash, self.currentOS, self.username)
            except FileNotFoundError:
                pass  # Username updated
        writetoFile(encUsrName, passIdHash, self.currentOS, self.username)
        writetoFile(encPassword, aadHash, self.currentOS, self.username)
        print("\nPassword saved successfully!\n")

    def getPassword(self):
        self.displayPassIds()
        print("=== Get Password ===")
        # Retrieving password
        passId = readPassId()
        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        try:
            encUsrName = readfromFile(
                passIdHash, self.currentOS, self.username)
        except FileNotFoundError:
            logging.error("Incorrect Password ID.")
            print("Error: Incorrect Input.")
            return

        # Decrypting username
        usrAad = passId.encode("utf-8")
        nonce_hash = sha256(passId.encode("utf-8")).hexdigest()
        baseNonce = nonce_hash[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad,
                              baseNonce).decode("utf-8")
        except InvalidTag:
            print("Error: Incorrect Input.")
            return

        # decrypting password
        passAad = (passId + usrName).encode("utf-8")
        aadHash = sha256(passAad).hexdigest()
        # Read Encrypted password
        try:
            encPassword = readfromFile(aadHash, self.currentOS, self.username)
        except FileNotFoundError:
            logging.error("Cannot read password file %s", aadHash)
            print("Error: Something went wrong. Try again!")
            return

        passIdHash = sha256(passId.encode("utf-8")).hexdigest()
        # Use PBKDF2 to derive nonce from password securely
        passNonce = pbkdf2_hmac(
            "sha256",
            self.mPassword.encode("utf-8"),
            passIdHash.encode("utf-8"),
            480000
        )[:12]

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
            encUsrName = readfromFile(
                passIdHash, self.currentOS, self.username)
            deleteFile(passIdHash, self.currentOS, self.username)
        except FileNotFoundError:
            logging.error("Incorrect Password ID.")
            print("Error: Incorrect Input.")
            return
        # Decrypting username
        usrAad = passId.encode("utf-8")
        nonce_hash = sha256(passId.encode("utf-8")).hexdigest()
        baseNonce = nonce_hash[:24].encode("utf-8")
        try:
            usrName = decrypt(self.mKey, encUsrName, usrAad,
                              baseNonce).decode("utf-8")
        except InvalidTag:
            print("Error: Incorrect Input.")
            return

        passAad = (passId + usrName).encode("utf-8")
        aadHash = sha256(passAad).hexdigest()

        # Delete password file
        try:
            deleteFile(aadHash, self.currentOS, self.username)
            self.removePassId(passId)
        except FileNotFoundError:
            logging.error("Cannot find password file %s", aadHash)
            print("Error: Something went wrong. Try again!")
            return
        print("\nPassword Deleted successfully!\n")

    def exportData(self):
        currentDateTime = str(datetime.datetime.now()).split(".")[
            0].replace(":", "").replace(" ", "-")
        try:
            if self.currentOS == "Windows":
                shutil.make_archive(currentDateTime, "zip", self.dataDir)
                return currentDateTime + ".zip"
            elif self.currentOS == "Linux":
                shutil.make_archive(currentDateTime, "gztar", self.dataDir)
                return currentDateTime + ".tar.gz"
            else:
                return None
        except (OSError, shutil.Error) as e:
            logging.error("Export failed: %s", str(e))
            return None

    def importData(self, backupFileName):
        shutil.rmtree(self.dataDir + '/')
        self.makeDataDirectory()
        shutil.unpack_archive(backupFileName, self.dataDir + '/')

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
                msg = ("All encrypted files will be exported to "
                       "current directory. Continue?")
                if readChoice(msg) == "y":
                    fileName = self.exportData()
                    if fileName is not None:
                        print(f"***Successful backup saved to: {fileName}")
                        print("***You should save this file on another "
                              "secured device.")
                    else:
                        print("Error: Unable to save a new backup file")
                if readChoice("Do you want to continue using CZar?") == "n":
                    stillRunning = False
                else:
                    mode = readMode()
            elif mode in ("import", "i"):
                fileName = readBackupFileName()
                msg = (f"Password data will be imported from {fileName}. "
                       "Current data could be lost or replaced. Continue?")
                if readChoice(msg) == "y":
                    try:
                        self.importData(fileName)
                        print("***Successful backup import")
                    except (shutil.Error, OSError) as e:
                        logging.error("Import failed: %s", str(e))
                        print("Error: Unable to import from backup file")
                msg = "Shutdown CZar and start it again. Confirm?"
                while readChoice(msg) == "n":
                    pass
                stillRunning = False
            else:
                logging.error("Undefined input mode!")
                print("Undefined input mode!")
                stillRunning = False

        # Clear clipboard before shutting down CZar
        copyToClipboard("")
        logging.info("Shutting down CZar ...")
        print("\nShutting down CZar ...")


def main(cliArgs):
    try:
        currentOS = platform.system()
        username, _, master_password = authenticate_user(currentOS)
        cZar = CZar(cliArgs, username, master_password)
        # Start Czar
        cZar.start()
    except KeyboardInterrupt:
        copyToClipboard("")
        logging.info("Shutting down CZar ...")
        print("\nShutting down CZar ...")


if __name__ == "__main__":
    main(args)
