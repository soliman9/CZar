import os
import ctypes


def writetoFile(dataBytes, fileName, currentOS):
    if currentOS == 'Windows':
        path = 'data/{}'.format(fileName)
        with open(path, "wb") as bFile:
            bFile.write(dataBytes)
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)
    elif currentOS == 'Linux':
        path = '.data/.{}'.format(fileName)
        with open(path, "wb") as bFile:
            bFile.write(dataBytes)


def readfromFile(fileName, currentOS):
    if currentOS == 'Windows':
        path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        path = '.data/.{}'.format(fileName)

    with open(path, "rb") as bFile:
        dataBytes = bFile.read()
    return dataBytes


def deleteFile(fileName, currentOS):
    if currentOS == 'Windows':
        path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        path = '.data/.{}'.format(fileName)

    os.remove(path)


def appendToTextFile(data, fileName, currentOS):
    if currentOS == 'Windows':
        path = 'data/{}'.format(fileName)
        with open(path, "a") as f:
            f.write(data + '\n')
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)
    elif currentOS == 'Linux':
        path = '.data/.{}'.format(fileName)
        with open(path, "a") as f:
            f.write(data + '\n')


def readfromTextFile(fileName, currentOS):
    if currentOS == 'Windows':
        path = 'data/{}'.format(fileName)
    elif currentOS == 'Linux':
        path = '.data/.{}'.format(fileName)

    try:
        with open(path, "r") as f:
            lines = f.read().split('\n')
            lines.remove('')
    except FileNotFoundError:
        with open(path, "a") as f:
            pass
        lines = []
    return lines
