def writetoFile(dataBytes, fileName):
    path = 'data/{}'.format(fileName)
    with open(path, "wb") as bFile:
        bFile.write(dataBytes)


def readfromFile(fileName):
    path = 'data/{}'.format(fileName)
    with open(path, "rb") as bFile:
        dataBytes = bFile.read()
    return dataBytes
