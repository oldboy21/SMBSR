#!/usr/bin/python3

#
# Author:
#  @oldboy21
#  https://github.com/oldboy21/smbsr/ 

import socket
import argparse
import logging
import sys
import ipaddress 
import urllib
import tempfile
import re
from smb import *
from smb.SMBConnection import SMBConnection
from smb.SMBHandler import SMBHandler
from io import BytesIO
import masscan
import _thread
import threading
from threading import Lock
from threading import Thread
import random
import uuid
import sys
import os
import sqlite3
import csv
from itertools import compress 
import datetime
import faulthandler
import concurrent.futures
import gc
import time
import io
import string
import textract
import ldaphelper

class Database:
    def __init__(self,db_file):
        self.db_file=db_file


    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.lock = threading.Lock()

    def create_database(self):
        self.connect_database()
        try:
            smb_match_table = """ CREATE TABLE IF NOT EXISTS smbsr (
                                            id integer PRIMARY KEY AUTOINCREMENT,
                                            file text NOT NULL,
                                            share text NOT NULL,
                                            ip text NOT NULL,
                                            position text NOT NULL,
                                            matchedWith text NOT NULL,
                                            tsCreated text NOT NULL,
                                            tsModified text NOT NULL, 
                                            tsAccessed text NOT NULL,
                                            count integer NOT NULL  
                                        ); """
            smb_files_table = """ CREATE TABLE IF NOT EXISTS smbfile (
                                id integer PRIMARY KEY AUTOINCREMENT,
                                file text NOT NULL,
                                share text NOT NULL,
                                ip text NOT NULL,
                                tsCreated text NOT NULL,
                                tsModified text NOT NULL,
                                tsAccessed text NOT NULL

                            ); """
            smb_write_table = """ CREATE TABLE IF NOT EXISTS smbwriterights (
                                shareIp text PRIMARY KEY,                                
                                writable integer NOT NULL

                            ); """                            
                                
    

            if self.cursor is not None:
                self.create_table(smb_match_table)
                self.create_table(smb_files_table)
                self.create_table(smb_write_table)
        except Exception as e: 
          logger.error("Encountered error while creating the database: " + str(e))
          sys.exit(1)

    def exportToCSV(self):
        cursor = self.cursor
        exportQuery = "SELECT * from smbsr"
        exportQueryFile = "SELECT * from smbfile"
        exportWritableQuery = "SELECT * from smbwriterights"
        sr = cursor.execute(exportQuery)
        with open('smbsr_results.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerows(sr)        
        sf = cursor.execute(exportQueryFile)
        with open('smbsrfile_results.csv', 'w') as g:
            writer = csv.writer(g)
            writer.writerows(sf)    
        sw = cursor.execute(exportWritableQuery)
        with open('smbsrwritable_results.csv', 'w') as h:
            writer = csv.writer(h)
            writer.writerows(sw)    



    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):

        try:
            self.cursor.execute(create_table_sql)
        except Exception as e:
            logger.info(e)

    def insertFinding(self, filename, share, ip, line, matched_with ,times):
         
         try: 
           self.lock.acquire(True) 
           cursor = self.cursor
           checkQuery = 'SELECT id FROM smbsr WHERE ip=\'{ip}\' AND share=\'{share}\' AND file=\'{filename}\''.format(ip=ip, share=share, filename=filename)
           results = cursor.execute(checkQuery).fetchall()
           if len(results) == 0:
               insertFindingQuery = "INSERT INTO smbsr (file, share, ip, position, matchedWith, tsCreated, tsModified, tsAccessed, count) VALUES (?,?,?,?,?,?,?,?,?)"
               cursor.execute(insertFindingQuery, (filename, share, ip, line, matched_with, times[0], times[1], times[2], 1))
               self.commit()
           else: 
                updateQuery = 'UPDATE smbsr SET count = count + 1 WHERE ip=\'{ip}\' AND share=\'{share}\' AND file=\'{filename}\''.format(ip=ip, share=share, filename=filename)
                cursor.execute(updateQuery)
                self.commit()  
         finally: 
           self.lock.release()  

    def insertFileFinding(self, filename, share, ip, times):
         
         try: 
           self.lock.acquire(True)         
           cursor = self.cursor
           insertFindingQuery = "INSERT INTO smbfile (file, share, ip, tsCreated, tsModified, tsAccessed) VALUES (?,?,?,?,?,?)"
           cursor.execute(insertFindingQuery, (filename, share, ip, times[0], times[1], times[2]))
           self.commit()  
         finally: 
            self.lock.release()

    def insertWritableCount(self, share, ip, writable):
         
         try: 
           self.lock.acquire(True)         
           cursor = self.cursor
           insertWritableQuery = "INSERT INTO smbwriterights (shareIp, writable) VALUES (?,?) ON CONFLICT(shareIp) DO UPDATE SET writable=?"
           cursor.execute(insertWritableQuery, (share+"/"+ip, writable, writable))
           self.commit()  
         finally: 
            self.lock.release()                        
                

class HW(object):
    def __init__(self, options, db):
        super(HW, self).__init__()
        self.options = options 
        self.conn = SMBConnection(options.username,options.password,options.fake_hostname,'netbios-server-name',options.domain,use_ntlm_v2=True,is_direct_tcp=True) 
        self.db = db 

    def retrieveTextSpecial(self, file_object):
        try:
            #os.rename(file_object.name, file_object.name + ".docx")
            text = textract.process(file_object.name)
                           
            return text     
        except Exception as e: 
            os.remove(file_object.name)
            logger.error("Error while parsing special file " + file_object.name + " with exception: " + str(e))
            return "textractfailed"


    def get_bool(self,prompt):
        while True:
            try:
               return {"y":True,"n":False}[input(prompt).lower()]
            except KeyError:
               print("Invalid input please enter [y/n]")

    def retrieveTimes(self, share, filename):
        times = []
        attributes = self.conn.getAttributes(share, filename)
        ts_created = datetime.datetime.fromtimestamp(attributes.create_time).strftime('%Y-%m-%d %H:%M:%S')
        ts_accessed = datetime.datetime.fromtimestamp(attributes.last_access_time).strftime('%Y-%m-%d %H:%M:%S')
        ts_modified = datetime.datetime.fromtimestamp(attributes.last_write_time).strftime('%Y-%m-%d %H:%M:%S')
        times.append(ts_created)
        times.append(ts_modified)
        times.append(ts_accessed)
        return times 

    def passwordHW(self,text, filename,to_match, counter, IP, share):
        results = []
        output = False
        
        words =to_match["words"]
        regex = to_match["regex"]
        
        for substring in words: 
            results.append(substring.lower() in text.lower())
        output=any(results)        
        if output: 
            m = [i for i, x in enumerate(results) if x]
            for z in m:
                logger.info("Found interesting match in " + filename + " with " + words[z] +", line: " + str(counter)) 
                self.db.insertFinding(filename, share, IP, str(counter), words[z], self.retrieveTimes(share,filename))
                return True    
        if len(regex) > 0:

            for i in regex:        
                if re.search(i, text):
                    logger.info("Found interesting match in " + filename + " with regex " + i +", line: " + str(counter))
                    self.db.insertFinding(filename, share, IP, str(counter), i, self.retrieveTimes(share,filename))
                    return True
        return False              


    def parse(self, share, filename, to_match, IP):
        line_counter = 0 
        hits = 0 
        file_obj = tempfile.NamedTemporaryFile()
        file_ext = (filename.split('/')[-1]).split('.')[-1] or "empty"
        #file_ext_double = (filename.split('/')[-1]).split('.')[-2] or "empty"
        # or file_ext_double.lower() in self.options.file_extensions_black.split(',')
        if file_ext.lower() in self.options.file_extensions_black.split(','):
            logger.info("This extensions is blacklisted")
        else:
            if file_ext.lower() in self.options.file_interesting.split(','):
               logger.info("Found interesting file: " + filename)
               self.db.insertFileFinding(filename, share, IP, self.retrieveTimes(share,filename))
            if (filename.split('/')[-1]).split('.')[0].lower() in to_match["words"]:
               logger.info("Found interesting file named " + filename)
               self.db.insertFileFinding(filename, share, IP, self.retrieveTimes(share,filename))      
            
            filesize = (self.conn.getAttributes(share, filename)).file_size        
            if filesize > self.options.max_size:
                logger.info("Skipping file " + filename + ", it is too big and you said i can't handle it")

            else:
                file_attributes, filesize = self.conn.retrieveFile(share, filename, file_obj)
                #here the extension check for office files 
                if file_ext.lower() in ['docx','doc','docx','eml','epub','gif','jpg','mp3','msg','odt','ogg','pdf','png','pptx','ps','rtf','tiff','tif','wav','xlsx','xls']:
                    specialfile = open(str(''.join(random.choices(string.ascii_uppercase, k = 5))) + "." +file_ext , "ab")
                    file_attributes, filesize = self.conn.retrieveFile(share, filename, specialfile)
                    #this mightbe empty AND GENERATE AND EXCEPTION
                    lines = (self.retrieveTextSpecial(specialfile))
                    specialfile.close()
                    if lines != "textractfailed":
                        lines = lines.split(b' ')                        
                        try:
                            os.remove(specialfile.name)
                        except Exception as e:
                            logger.warning("Error deleting the temp file: " + specialfile.name)    

                else:
                    file_obj.seek(0)                
                    lines = file_obj.readlines()
                    #need to work on the lines here bcs the strip with bytes does not work apparently 
                    

                if len(lines) > 0 and lines != "textractfailed": 
                  for line in lines: 
                    
                    line_counter+=1 
                    try: 
                        
                     if self.passwordHW((line.decode('utf-8')).strip('\n'), filename,to_match, line_counter, IP, share):
                          hits += 1
                          if hits >= options.hits:
                              logger.info("Reached max hits for " + filename)
                              break  
                    except Exception as e: 
                       logger.warning("Encountered exception while reading file: " + file_ext + " | Exception: " + str(e))
                       if isinstance(file_obj, (io.RawIOBase, io.BufferedIOBase)): #using filetype different from none? 
                          self.options.file_extensions_black = self.options.file_extensions_black + "," + file_ext
                       break
        file_obj.close()                                      
    

    def walk_path(self,path,shared_folder,IP,to_match):
           count = 0 
           try:
             for p in self.conn.listPath(shared_folder, path):
                 
                 
                 if p.filename!='.' and p.filename!='..':
                     parentPath = path
                     if not parentPath.endswith('/'):
                         parentPath += '/'
                     if p.isDirectory:   
                         
                         if p.filename.lower() in self.options.folder_black.split(','):
                           logger.info('Skipping ' + p.filename + " since blacklisted")   

                           continue
                         else:  
                            if parentPath.count('/') <= self.options.depth: 
                              
                              logger.info("Visiting subfolder " + str(p.filename))  
                              try:
                                 count = count + self.walk_path(parentPath+p.filename,shared_folder,IP,to_match)
                              except Exception as e:
                                  logger.error("Error while accessing folder: " + parentPath+p.filename)
                                  continue
                              #IF IT FAILS WITH A FOLDER IT SHOULD TRY TO MOVE FORWARD 
                            else:
                               logger.info("Skipping " + str(parentPath+p.filename) + ", too deep")                              
                               continue  
                     else:
                         logger.info( 'File: '+ parentPath+p.filename )
                         if  not p.isReadOnly:
                            
                            count+=1
                            
                            self.db.insertWritableCount(shared_folder,IP,count) 
                         self.parse(shared_folder, parentPath+p.filename, to_match, IP)
           
             return count               
           except Exception as e: 
              logger.warning("Error while listing paths in shares: " + str(e))


                            
    

    def shareAnalyze(self,IPaddress, to_match):
       for ip in IPaddress:
         logger.info("Checking SMB share on: " + ip)
         #domain_name = 'domainname'
         #conn = SMBConnection(options.username,options.password,options.fake_hostname,'netbios-server-name','SECRET.LOCAL',use_ntlm_v2=True,is_direct_tcp=True)
         try:
            self.conn.connect(ip, 445)
         except Exception as e:
             logger.warning("Detected error while connecting to " + str(ip) + " with message " + str(e))
             continue  
         try:   
           shares = self.conn.listShares()

         except Exception as e:
           logger.warning("Detected error while listing shares on "  + str(ip) + " with message " + str(e)) 
           continue 
         for share in shares:
             if not share.isSpecial and share.name not in ['NETLOGON', 'IPC$'] and share.name not in self.options.share_black.split(','):
                logger.info('Listing file in share: ' + share.name)
                try:
                   sharedfiles = self.conn.listPath(share.name, '/') ##THIS CHECK IS NOT ENOUGH IF IT FAILS ON A FOLDER
                except Exception as e:  
                    logger.warning("Detected error while listing shares on "  + str(ip) + " with message " + str(e)) 
                    continue
                self.walk_path("/",share.name,ip, to_match)
         self.conn.close()   

    def shareAnalyzeLightning(self,to_analyze, to_match):
       
       ip = to_analyze.pop(0)
       logger.info("Checking SMB share on: " + ip)
       #domain_name = 'domainname'
       #conn = SMBConnection(options.username,options.password,options.fake_hostname,'netbios-server-name','SECRET.LOCAL',use_ntlm_v2=True,is_direct_tcp=True)
       try:
          self.conn.connect(ip, 445)          
          shares = self.conn.listShares()
          for share in shares:

            if not share.isSpecial and share.name not in ['NETLOGON', 'IPC$'] and share.name not in self.options.share_black.split(','): 
                   logger.info('Listing file in share: ' + share.name)
                   self.walk_path("/",share.name,ip, to_match)
       except Exception as e:
           logger.info("Detected error while listing shares on "  + str(ip) + " with message " + str(e))
            

       self.conn.close()
       
    def extractCIDR(self,final ):
        cidr = []
        for target in final: 
            ipcheck = re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]{1,2}))$", target)
            if ipcheck: 
                cidr.append(target)
        return cidr 



    def scanNetwork(self):
       target = self.options.IP
       file_target = self.options.ip_list_path
       temp = []
       final = []
       ldap_targets = []
       to_analyze = []
       #here it goes the LDAP check function
       if self.options.ldap:
           logger.info("Retrieving computer objects from LDAP. KINIT process might take some time, be patient")
           #ldapoptions =self.options
           #ldapoptions.username = self.options.domain + "\\" + self.options.username 
           ldaphelperQ = ldaphelper.LDAPHelper(self.options)
           ldaphelperQ.kerberosAuth()
           ldap_targets = ldaphelperQ.retrieveComputerObjects()
           #ldap_targets = smbsrldap.run(ldapoptions)           
           #self.options.username = (self.options.username.split('\\')[1])
                
       if file_target != "unset":
         with open(file_target) as f:
           temp = [line.rstrip() for line in f]
         f.close()
       else: 
          temp.append(target)
       temp = temp + ldap_targets

       temp = list( dict.fromkeys(temp) )
       
       for i in temp:        
          try:
            valid = re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}($|\/([0-9]{1,2}))$", i) 
          except Exception as e: 
            logger.warning("exception reading from initial list")
            continue        
          if not valid:
               logger.info("You entered an hostname, looking up " + i)
               try:
                 ldapt = (socket.gethostbyname(i)).strip('\n')
                 
                 final.append(ldapt)

               except socket.gaierror: 
                   logger.warning("Hostname could not be resolved: " + i)
                   
          else: 
              final.append(i)

       
       cidrs = list(dict.fromkeys(self.extractCIDR(final)))
       final = list(dict.fromkeys(final))


       for i in cidrs:
         if i in final:            
            final.remove(i)




       if not self.options.masscan:
          if len(final) == 0 and len(cidrs) > 0: #case only one input is given and it is a CIDR
            logger.error("Hey there, if you do not use masscan you can't give me CIDR as input")
            sys.exit(1)
          for x in final:
             ipcheck = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", x)
             if not ipcheck: 
                logger.error("Hey there, if you do not use masscan you can't give me CIDR as input")
                sys.exit(1)
          return final      
       logger.info('Starting masscan to discover SMB ports open')
       mass = masscan.PortScanner()
       if len(cidrs) > 0: 
            for ni in cidrs:
                try:
                   mass.scan(ni, ports='445', arguments='--rate 1000') 
                   for key in mass.scan_result['scan']:
                      if mass.scan_result['scan'][key]['tcp'][445]['state'] == 'open':
                             to_analyze.append(key)       
                except Exception as e: 
                   logger.error("masscan failed with error: " + str(e) + " for range: " + str(ni))
                   
       if len(final) > 0:
            ranges = ','.join(final)
            try:
               mass.scan(ranges, ports='445', arguments='--rate 1000')        
            except Exception as e: 
               logger.error("masscan failed with error: " + str(e))               
               sys.exit(1)
              
            for key in mass.scan_result['scan']:
              if mass.scan_result['scan'][key]['tcp'][445]['state'] == 'open':
                     to_analyze.append(key)

       return to_analyze

    def readMatches(self):
        filepath = self.options.word_list_path
        file_regular = self.options.regular_exp
        rlines = []
        try: 
           with open(filepath) as f:
             lines = [line.rstrip() for line in f]
           f.close()
           #return lines
        except Exception as e:
            logger.error("Exception while reading the file " + str(e))
            sys.exit(1)   
        if file_regular != 'unset':
            
            try: 
                with open(file_regular) as r:
                    rlines = [line.rstrip() for line in r]
                r.close()
            except Exception as e:
                logger.error("Exception while reading the regular expression file " + str(e))
                
        to_match_dict = {

        "words" : lines,
        "regex" : rlines
        } 
        return to_match_dict


class smbworker (threading.Thread):
   def __init__(self, name, options, ip_list, to_match, db):
      threading.Thread.__init__(self)
      #self.threadID = threadID
      self.name = name
      self.options = options
      self.ip = ip_list
      self.to_match = to_match
      self.db = db
   def run(self):
      logger.info("Starting " + self.name)
      smbHW = HW(self.options, self.db)
      logger.info("Tasks queue lenght: " + str(len(self.ip)))
      while (len(self.ip) > 0):
            smbHW.shareAnalyzeLightning(self.ip, self.to_match)
      
      logger.info("Tasks queue lenght: " + str(len(self.ip)))
      logger.info("Exiting " + self.name)

   

def setupPersistence(db, dbfile):
    if not os.path.exists(dbfile):
        logger.info("Database not found, creating ...")
        db.create_database()
        logger.info("Database created successfully")
    else:
        logger.info("Database already existing")
        db.connect_database()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(add_help=True, description="SMB Password Revealer ")
    parser.add_argument('-username', action='store', default='anonymous',type=str, help='Username for authenticated scan')
    parser.add_argument('-password', action='store', default='s3cret', type=str, help='Password for authenticated scan')
    parser.add_argument('-domain', action='store', default='SECRET.LOCAL', help='Domain for authenticated scan')
    parser.add_argument('-fake-hostname', action='store', default='localhost', help='Computer hostname SMB connection will be from')
    parser.add_argument('-word-list-path', action="store", type=str, help="File containing the string to look for", required=True)
    parser.add_argument('-max-size', action="store", default=50000 ,type=int, help="Maximum size of the file to be considered for scanning (bytes)")
    parser.add_argument('-file-extensions-black', action='store', type=str, default='none', help='Comma separated file extensions to skip while secrets harvesting')
    parser.add_argument('-multithread', action='store_true', default=False, help="Assign a thread to any IP to scan")
    parser.add_argument('-masscan', action='store_true', default=False, help="Scan for 445 before trying to analyze the share")
    parser.add_argument('-T', action='store', default=10, type=int, help="Define the number of thread to use")
    parser.add_argument('-logfile', action='store', default='smbsr.log', type=str, help='Log file name')
    parser.add_argument('-dbfile', action='store', default='./smbsr.db', type=str, help='Log file name')
    parser.add_argument('-file-interesting', action='store', default='none', type=str, help='Comma separated file extensions you want to be notified about')
    parser.add_argument('-folder-black', action='store', default='none', type=str, help='Comma separated folder names to skip during the analysis, keep in mind subfolders are also skipped')
    parser.add_argument('-csv', action='store_true', default=False, help='Export results to CSV files in the project folder')
    parser.add_argument('-depth', action='store', default=100000000, type=int, help='How recursively deep you want to go while looking for secrets')
    parser.add_argument('-regular-exp', action="store", default='unset' ,type=str, help="File containing regex expression to match")
    parser.add_argument('-share-black', action='store', type=str, default='none', help='Comma separated share names to skip while secrets harvesting')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-ip-list-path', action="store", default="unset", type=str, help="File containing IP to scan")
    group.add_argument('-IP',action="store", help='IP address, CIDR or hostname')
    #ldapgroup = parser.add_mutually_inclusive_group()
    parser.add_argument('-fqdn', action='store', help='FQDN for KINIT')
    parser.add_argument('-ldap', action='store_true', default=False, help='Query LDAP to retrieve the list of computer objects in a given domain')
    parser.add_argument('-dc-ip', action='store', help='DC IP of the domain you want to retrieve computer objects from')
    parser.add_argument('-hits', action='store',default=5000 ,type=int, help='Max findings per file')
   

    options = parser.parse_args()

    if options.ldap and not options.fqdn: 
        parser.error ('If you want to retrieve computer objects from LDAP please provide a FQDN to retrieve your TGT')
    faulthandler.enable()
    formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s')

    logger = logging.getLogger('logger')
    #cleaning handlers 
    logging.getLogger().handlers = []
    logger.handlers = []
    logger.setLevel(logging.INFO)

    infoHandler = logging.FileHandler(options.logfile)
    infoHandler.setLevel(logging.INFO)
    infoHandler.setFormatter(formatter)
    
    stdoutHandler = logging.StreamHandler(sys.stdout)
    stdoutHandler.setLevel(logging.INFO)
    stdoutHandler.setFormatter(formatter)

    logger.addHandler(stdoutHandler)
    logger.addHandler(infoHandler)

    if len(sys.argv)==1:
        parser.print_help()
        print ("\nExamples: ")
        print("\t./smb-secrets-revealer.py -IP 127.0.0.1/localhost -word-list-path tomatch.txt\n")
        sys.exit(1)
    
    db = Database(options.dbfile)
    setupPersistence(db, options.dbfile)

    
    smbHW = HW(options, db)
    to_match = smbHW.readMatches()
    to_analyze = smbHW.scanNetwork()
    #TO REMOVE 
    
    logger.info("Total amounts of targets: " + str(len(to_analyze)))
    threads = []
    if options.multithread is True: 
        logger.info("Lighting!!")
        if len(to_analyze) < options.T:
            options.T = len(to_analyze)
        for i in range(options.T):            
            try:
                
                worker = smbworker("Worker-" + str(i+1), options, to_analyze, to_match, db)                
                worker.start()
                threads.append(worker)
            except Exception as e: 
                logger.error("Error while multithreading: " + str(e))
                sys.exit(1)
            

        for thread in threads:
            thread.join()          
       
                             
    else:     
        smbHW.shareAnalyze(to_analyze, to_match)
    if options.csv:
       db.exportToCSV()
    print ("Hope you found something good mate!")
    










