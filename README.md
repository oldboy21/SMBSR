# SMBSR - what is that? 

Well, SMBSR is a python script which given a CIDR/IP/IP_file/HOSTNAME(s) enumerates all the SMB services listening (445) among the targets 
and tries to authenticate against them; if the authentication succeed then all the folders and subfolders are visited recursively 
in order to find secrets in files and ... secret files. In order to scan the targets for SMB ports open the masscan module is used.
SMBSR consides someting interesting  basing on its: 

* Content
* Exstension 
* Name

The interesting keywords the tool should look for are defined via the command line as well as: 

* File extension blacklist
* Folder blacklist (Watch out, also subfolders are gone)
* Number of Threads
* Should i masscan or not?
* Interesting file extensions (I guess something like ppk, kdbx, ...)
* Maximum file size (Bytes) allowed to be checked (Believe me, too big might take some time) 
* Should i export the results in two nice CSV files? 
* How deep should i look into subfolders?
* Other common ones and required 

Of course everything is saved locally in a SQlite Database. The database containes one table for the "hopefully it's a DA password" match, called smbsr containing the 
following columns: 

* file
* share
* ip 
* position
* matchedWith
* Creation Date
* Last Modified Date
* Last Accessed Date
* Count (If more then one match on the same file, this one is incremented)

And also another table for the interesting file list containing the following columns: 

* file 
* share
* ip
* Creation Date
* Last Modified Date
* Last Accessed Date

## Requirements

```bash
pip3 install -r requirements.txt
```

## Usage

For instance, from the project folder:

```bash
./smbsr.py -IP 127.0.0.1 -word-list-path tomatch.txt -multithread -max-size 1000 -T 2 -username OB -password '****' -domain OB -file-extensions dll,exe,bin
```
## Coming Soon(?)

* LDAP Integration in order to retrieve the list of computer objects

# Credits 

* Everyone who is going to help out finding issues and improving 
* [Retrospected](https://github.com/Retrospected): For helping out every Friday with debugging the code and brainstorming on new features
