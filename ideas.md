1. generate passwords for user -->> let user choose password length**
2. min requirements for a strong master password
3. Use distributed storage instead of centralized storage.
4. **Version2.0.0** >> list pass IDs [*optional*] if user forgets one. [NOT_SECURE]
5. When saving, check if Pass ID was previously used. Also, Catch exceptions when writing a file. ******
6. Consider using passwords with Fernet.
## New version
1. Clear clipboard after timeout = 60 seconds.

# TODO
* Use colored structured table too display password ids. [Done] but Not colored
* Add export and import backup [DONE]
* Encrypt the backup zip file (using master password hash as the key) before exporting it.
* Automatic backup data. (monthly, weekly, daily)

* Password Health Check: Analyze the strength and security of existing passwords, and prompt users to update weak or compromised passwords.
* Password Expiry & Renewal Reminders: Set reminders for password expiry and renewal, helping users stay proactive in maintaining their online security.
* Custom Categories & Tags: Organize passwords and data into custom categories and add tags for easy searching and filtering.

# Error
Do you want to continue using CZar? yes[y]/No[n]:Exception in thread Thread-2:
Traceback (most recent call last):
  File "threading.py", line 973, in _bootstrap_inner
  File "threading.py", line 910, in run
  File "startCzar.py", line 96, in clipboardTimer
  File "ioUtils\clipboardUtils.py", line 8, in clearClipboard
  File "pyperclip\__init__.py", line 471, in copy_windows
  File "contextlib.py", line 119, in __enter__
  File "pyperclip\__init__.py", line 452, in clipboard
pyperclip.PyperclipWindowsException: Error calling OpenClipboard ([WinError 5] Access is denied.)
