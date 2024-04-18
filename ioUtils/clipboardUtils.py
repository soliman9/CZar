import pyperclip


def copyToClipboard(txt):
    pyperclip.copy(txt)

def clearClipboard():
    pyperclip.copy(" ")

