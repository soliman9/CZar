import os
import ctypes


def writetoFile(dataBytes, fileName, currentOS, username=None):
    if currentOS == 'Windows':
        if username:
            path = f'data/{username}/{fileName}'
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            path = 'data/{}'.format(fileName)
        with open(path, "wb") as bFile:
            bFile.write(dataBytes)
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)
    elif currentOS == 'Linux':
        if username:
            path = f'.data/{username}/.{fileName}'
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            path = '.data/.{}'.format(fileName)
        with open(path, "wb") as bFile:
            bFile.write(dataBytes)


def readfromFile(fileName, currentOS, username=None):
    if currentOS == 'Windows':
        if username:
            path = f'data/{username}/{fileName}'
        else:
            path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        if username:
            path = f'.data/{username}/.{fileName}'
        else:
            path = '.data/.{}'.format(fileName)
    else:
        raise ValueError(f"Unsupported OS: {currentOS}")

    with open(path, "rb") as bFile:
        dataBytes = bFile.read()
    return dataBytes


def deleteFile(fileName, currentOS, username=None):
    if currentOS == 'Windows':
        if username:
            path = f'data/{username}/{fileName}'
        else:
            path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        if username:
            path = f'.data/{username}/.{fileName}'
        else:
            path = '.data/.{}'.format(fileName)
    else:
        raise ValueError(f"Unsupported OS: {currentOS}")

    os.remove(path)


def appendToTextFile(data, fileName, currentOS, username=None):
    if currentOS == 'Windows':
        if username:
            path = f'data/{username}/{fileName}'
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            path = 'data/{}'.format(fileName)
        with open(path, "a", encoding="utf-8") as f:
            f.write(data + '\n')
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)
    elif currentOS == 'Linux':
        if username:
            path = f'.data/{username}/.{fileName}'
            os.makedirs(os.path.dirname(path), exist_ok=True)
        else:
            path = '.data/.{}'.format(fileName)
        with open(path, "a", encoding="utf-8") as f:
            f.write(data + '\n')


def readfromTextFile(fileName, currentOS, username=None):
    if currentOS == 'Windows':
        if username:
            path = f'data/{username}/{fileName}'
        else:
            path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        if username:
            path = f'.data/{username}/.{fileName}'
        else:
            path = '.data/.{}'.format(fileName)
    else:
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.read().split('\n')
            lines.remove('')
    except FileNotFoundError:
        with open(path, "a", encoding="utf-8") as f:
            pass
        lines = []
    return lines
