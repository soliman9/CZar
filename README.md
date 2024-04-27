# CZar Password Manager
CZar is a lightweight secure open source CLI password manager.

## Features
* **Simplified Design:** Simple CLI-based password manager.
* **Secure Password Generation:** Generate strong randomized passwords for each account, ensuring maximum security.
* **Password Storage & Encryption:** Safely store passwords using the strong AES-256 authenticated encryption.
* **Data Backup:** Easy and secure backup of encrypted passwords.

## Run from source code

* Installing required dependencies 

    `pip install -r requirements.txt`


* To create Master password and add or update your accounts usernames and passwords

    `python startCzar.py -m set`


* To retrieve your accounts usernames and passwords using the Master password

    `python startCzar.py -m get`
  

* To delete accounts usernames and passwords using the Master password

    `python startCzar.py -m del`


## Backup
The `/data` directory/folder that is created in the current working directory contains all encrypted passwords information. You can _safely_ backup this folder regularly to another device or cloud storage.
