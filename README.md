# SMBSR - what is that? 

Well, SMBSR is a python script which given a CIDR/IP/IP_file/HOSTNAME(s) enumerates all the SMB services listening (445) among the targets 
and tries to authenticate against them; if the authentication succeed then all the folders and subfolders are visited recursively 
in order to find secrets in files and ... secret files. In order to scan the targets for SMB ports open the masscan module is used.
SMBSR consides someting interesting  basing on its: 

* Content
* Exstension 
* Name

The interesting keywords the tool should look for are defined via the command line as well as: 

* File extension blacklist (this list is automatically updated at runtime basing on the exception thrown by the thread and the file type) 
* Shares blacklist
* Folder blacklist (Watch out, also subfolders are gone)
* Number of Threads
* Should i masscan or not?
* Interesting file extensions (I guess something like ppk, kdbx, ...)
* Maximum file size (Bytes) allowed to be checked (Believe me, too big might take some time) 
* Should i export the results in two nice CSV files? 
* How deep should i look into subfolders?
* Wordlist of regular expression to match 
* Domain Controller IP for ldap bind 
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

## File Supported

SMBSR learned how to read: 

* .csv via python builtins
* .doc via antiword
* .docx via python-docx2txt
* .eml via python builtins
* .epub via ebooklib
* .gif via tesseract-ocr
* .jpg and .jpeg via tesseract-ocr
* .json via python builtins
* .html and .htm via beautifulsoup4
* .mp3 via sox, SpeechRecognition, and pocketsphinx
* .msg via msg-extractor
* .odt via python builtins
* .ogg via sox, SpeechRecognition, and pocketsphinx
* .pdf via pdftotext (default) or pdfminer* .six
* .png via tesseract-ocr
* .pptx via python-pptx
* .ps via ps2text
* .rtf via unrtf
* .tiff and .tif via tesseract-ocr
* .txt via python builtins
* .wav via SpeechRecognition and pocketsphinx
* .xlsx via xlrd
* .xls via xlrd

## LDAP 

It is finally here! Now the domain credentials specified for SMB connections can also be used  in order to retrieve the list of computer objects from Active Directory.  

## reg_gen.py 

As the last update SMBSR has been granted with the power of looking for secrets that match a given regular expression (see regulars.txt file containing some good examples to
to match). Given this new super power i have also implemented a new script which given a wordlist it generates a list of regular expression which match the password patterns
it found into the wordlist. Before printing out everything the list of regular expression is (sort -u)-ed. The script can be optimized in case the pattern presents for example 
two or more ascii_lower in a row, but it's not like that now. 

## Requirements

```bash
pip3 install -r requirements.txt
```
Please also do install:

* krb5
* libkrb5-dev

## Usage

For instance, from the project folder:

```bash
./smbsr.py -IP 127.0.0.1 -word-list-path tomatch.txt -multithread -max-size 1000 -T 2 -username OB -password '****' -domain OB -file-extensions dll,exe,bin
```

# Credits 

* Everyone who is going to help out finding issues and improving 
* [Retrospected](https://github.com/Retrospected): For helping out every Friday with debugging the code and brainstorming on new features
* [ropnop](https://github.com/ropnop): For the work done on windapsearch.py
