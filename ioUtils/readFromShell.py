import os
from maskpass import askpass


def readChoice(question):
    choice = ''
    while True:
        choice = input(
            question + ' yes[y]/No[n]:'
        )
        if choice.lower() == 'y':
            break
        elif choice.lower() == 'n':
            break
        else:
            continue
    return choice.lower()


def readPassId():
    passId = ''
    while len(passId) == 0:
        passId = input(
            'Enter your password ID [example: facebook]: '
        )
    return passId


def readUserName(passId):
    usrName = ''
    while len(usrName) == 0:
        usrName = input(
            'Enter your {}\'s User Name: '.format(
                str(passId)
            )
        )
    return usrName


def readPassword(passId):
    password = ''
    while len(password) == 0:
        password = askpass(
            prompt='Enter your {}\'sPassword: '.format(
                str(passId)
            ),
            mask=''
        )
    return password


def readMode():
    supportedModes = set(['get', 'set', 'del', 'export',
                         'import', 'g', 's', 'd', 'e', 'i'])
    mode = ''
    while (len(mode) == 0 or (mode not in supportedModes)):
        mode = input(
            'Enter CZar starting mode [get (g), set (s), del (d), export(e), import(i)]: '
        ).lower()
    return mode


def readBackupFileName():
    fileName = ''
    while True:
        fileName = input(
            'Enter the name of the backup file. If not in current directory, you should provide a full path to it. '
        )
        if os.path.exists(fileName):
            splittedFileName = fileName.split('.')
            if len(fileName) != 0 and len(splittedFileName) > 1:
                if splittedFileName[-1] == 'zip':
                    break
                elif len(splittedFileName) > 2 and splittedFileName[-2] == 'tar' and splittedFileName[-1] == 'gz':
                    break
                else:
                    print('Error: check file name or the read permission.')
    return fileName


def readUsername():
    """Prompt user to enter a username."""
    username = ''
    while len(username) == 0:
        username = input('Enter your username: ').strip()
        if not username.isalnum():
            print('Error: Username must contain only letters and numbers.')
            username = ''
    return username


def readAuthChoice():
    """Prompt user to login or create account."""
    choice = ''
    while choice not in ('l', 'c'):
        choice = input(
            'Do you want to [l]ogin or [c]reate a new account? '
        ).lower().strip()
    return choice
