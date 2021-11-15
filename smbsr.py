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
import random
import uuid
import sys
import os
import sqlite3
import csv
from itertools import compress 
import datetime

class Database:
    def __init__(self,db_file):
        self.db_file=db_file

    def connect_database(self):
        self.conn = sqlite3.connect(self.db_file, check_same_thread=False)
        self.cursor = self.conn.cursor()

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
                                            tsAccessed text NOT NULL  
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
                                
    

            if self.cursor is not None:
                self.create_table(smb_match_table)
                self.create_table(smb_files_table)
        except Exception as e: 
          logger.error("Encountered error while creating the database: " + str(e))
          sys.exit(1)

    def exportToCSV(self):
        cursor = self.cursor
        exportQuery = "SELECT * from smbsr"
        exportQueryFile = "SELECT * from smbfile"
        sr = cursor.execute(exportQuery)
        with open('smbsr_results.csv', 'w') as f:
            writer = csv.writer(f)
            writer.writerows(sr)        
        sf = cursor.execute(exportQueryFile)
        with open('smbsrfile_results.csv', 'w') as g:
            writer = csv.writer(g)
            writer.writerows(sf)    




    def commit(self):
        self.conn.commit()

    def create_table(self, create_table_sql):

        try:
            self.cursor.execute(create_table_sql)
        except Exception as e:
            logger.info(e)

    def insertFinding(self, filename, share, ip, line, matched_with ,times):
         cursor = self.cursor
         insertFindingQuery = "INSERT INTO smbsr (file, share, ip, position, matchedWith, tsCreated, tsModified, tsAccessed) VALUES (?,?,?,?,?,?,?,?)"
         cursor.execute(insertFindingQuery, (filename, share, ip, line, matched_with, times[0], times[1], times[2]))
         self.commit()

    def insertFileFinding(self, filename, share, ip, times):
         cursor = self.cursor
         insertFindingQuery = "INSERT INTO smbfile (file, share, ip, tsCreated, tsModified, tsAccessed) VALUES (?,?,?,?,?,?)"
         cursor.execute(insertFindingQuery, (filename, share, ip, times[0], times[1], times[2]))
         self.commit()         
                

class HW(object):
    def __init__(self, options, db):
        super(HW, self).__init__()
        self.options = options 
        self.conn = SMBConnection(options.username,options.password,options.fake_hostname,'netbios-server-name',options.domain,use_ntlm_v2=True,is_direct_tcp=True) 
        self.db = db 

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
        for substring in to_match: 
            results.append(substring.lower() in text.lower())
        output=any(results)        
        if output: 
            m = [i for i, x in enumerate(results) if x]
            for z in m:
                logger.info("Found interesting match in " + filename + " with " + to_match[z] +", line: " + str(counter)) 
                self.db.insertFinding(filename, share, IP, str(counter), to_match[z], self.retrieveTimes(share,filename))   

    def parse(self, share, filename, to_match, IP):
        line_counter = 0 
        file_obj = tempfile.NamedTemporaryFile()
        file_ext = (filename.split('/')[-1]).split('.')[-1]
        if file_ext.lower() in self.options.file_extensions_black.split(','):
            logger.info("This extensions is blacklisted")
        else:
            if file_ext.lower() in self.options.file_interesting.split(','):
               logger.info("Found interesting file: " + filename)
               self.db.insertFileFinding(filename, share, IP, self.retrieveTimes(share,filename))
            if (filename.split('/')[-1]).split('.')[0].lower() in to_match:
               logger.info("Found interesting file named " + filename)
               self.db.insertFileFinding(filename, share, IP, self.retrieveTimes(share,filename))      
            
            filesize = (self.conn.getAttributes(share, filename)).file_size        
            if filesize > self.options.max_size: 
                bigF = self.get_bool("File size is bigger than the max size chosen, wish to continue?[y/n]")
                if bigF is True: 
                   file_attributes, filesize = self.conn.retrieveFile(share, filename, file_obj)
                   file_obj.seek(0)
                   lines = file_obj.readlines()
                   for line in lines: 
                     line_counter+=1
                     try:
                        self.passwordHW((line.decode("utf-8")).strip("\n"), filename,to_match, line_counter, IP, share)
                     except Exception as e: 
                         logger.info("Encountered exception while reading: " + str(e))
                         break   
                else: 
                    print ("I understand, i will proceed with the next file")
            else:
                file_attributes, filesize = self.conn.retrieveFile(share, filename, file_obj)
                file_obj.seek(0)
                lines = file_obj.readlines()
                for line in lines: 
                  line_counter+=1 
                  try: 
                   self.passwordHW((line.decode("utf-8")).strip("\n"), filename,to_match, line_counter, IP, share) 
                  except Exception as e: 
                     logger.warning("Encountered exception while reading: " + str(e))
                     break
            file_obj.close()                                      
    

    def walk_path(self,path,shared_folder,IP,to_match):
           #print (depth)
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

                              self.walk_path(parentPath+p.filename,shared_folder,IP,to_match)
                              
                            else:
                               logger.info("Skipping " + str(p.filename) + ", too deep")
                               #depth-=1
                               continue  
                     else:
                         logger.info( 'File: '+ parentPath+p.filename )
                         self.parse(shared_folder, parentPath+p.filename, to_match, IP)
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
             if not share.isSpecial and share.name not in ['NETLOGON', 'IPC$']:
                logger.info('Listing file in share: ' + share.name)
                try:
                   sharedfiles = self.conn.listPath(share.name, '/')
                except Exception as e:  
                    logger.warning("Detected error while listing shares on "  + str(ip) + " with message " + str(e)) 
                    continue
                self.walk_path("/",share.name,ip, to_match)
         self.conn.close()   

    def shareAnalyzeLightning(self,ip, to_match):
       
       logger.info("Checking SMB share on: " + ip)
       #domain_name = 'domainname'
       #conn = SMBConnection(options.username,options.password,options.fake_hostname,'netbios-server-name','SECRET.LOCAL',use_ntlm_v2=True,is_direct_tcp=True)
       try:
          self.conn.connect(ip, 445)
       except Exception as e:
           logger.info("Detected error while connecting to " + str(ip) + " with message " + str(e))
           sys.exit()
           ##NEED TO STOP HERE
       try:    
          shares = self.conn.listShares()
       except Exception as e:
           logger.info("Detected error while listing shares on "  + str(ip) + " with message " + str(e))
           sys.exit()    
       for share in shares:
           if not share.isSpecial and share.name not in ['NETLOGON', 'IPC$']:
              logger.info('Listing file in share: ' + share.name)
              try:
                 sharedfiles = self.conn.listPath(share.name, '/')
              except Exception as e: 
                 logger.warning("Could not list path on share " + share.name + " due to: " + str(e))   
              self.walk_path("/",share.name,ip, to_match)
       self.conn.close()       


    def scanNetwork(self):
       target = self.options.IP
       file_target = self.options.ip_list_path
       temp = []
       final = []
       if file_target != "unset":
         with open(file_target) as f:
           temp = [line.rstrip() for line in f]
         f.close()
       else: 
          temp.append(target)

       for i in temp:        
          valid = re.match("^([0-9]{1,3}\.){3}[0-9]{1,3}($|/([0-9]{1,2}))$", i)        
          if not valid:
               logger.info("You entered an hostname, looking up " + i)
               try:
                 final.append(socket.gethostbyname(i))
               except socket.gaierror: 
                   logger.warning("\nHostname could not be resolved: " + i)
                   #sys.exit(1)
          else: 
              final.append(i)         
       ranges = ','.join(final)
       
       if not self.options.masscan:
          for x in final:
             ipcheck = re.match("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", x)
             if not ipcheck: 
                logger.error("Hey there, if you do not use masscan you can't give me CIDR as input")
                sys.exit(1)
          return final      

       mass = masscan.PortScanner()
       mass.scan(ranges, ports='445', arguments='--rate 1000')        

       to_analyze = []
       logger.info('Starting masscan to discover SMB ports open')

       for key in mass.scan_result['scan']:
         if mass.scan_result['scan'][key]['tcp'][445]['state'] == 'open':
                to_analyze.append(key)

       return to_analyze

    def readMatches(self):
        filepath = self.options.word_list_path
        try: 
           with open(filepath) as f:
             lines = [line.rstrip() for line in f]
           f.close()
           return lines
        except Exception as e:
            logger.error("Exception while reading the file " + str(e))
            sys.exit(1)   


class smbworker (threading.Thread):
   def __init__(self, name, options, ip, to_match, db):
      threading.Thread.__init__(self)
      #self.threadID = threadID
      self.name = name
      self.options = options
      self.ip = ip
      self.to_match = to_match
      self.db = db
   def run(self):
      logger.info("Starting " + self.name)
      smbHW = HW(self.options, self.db)
      smbHW.shareAnalyzeLightning(self.ip, self.to_match)
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
    parser.add_argument('-max-size', action="store", default=50000 ,type=int, help="Maximum size of the file to be considered for scanning")
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
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-ip-list-path', action="store", default="unset", type=str, help="File containing IP to scan")
    group.add_argument('-IP',action="store", help='IP address, CIDR or hostname')
   
    options = parser.parse_args()

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
    if options.multithread is True: 

        
        #multithreading function call
        logger.info("Lighting!!")
        
        while len(to_analyze) > 0:
            if threading.active_count() <= options.T:
              try:
                worker = smbworker("Worker-" + str(uuid.uuid4())[:8], options, to_analyze[0], to_match, db)
                to_analyze.pop(0)
                worker.start()
                worker.join()
              except Exception as e: 
                logger.error("Error while multithreading: " + str(e))
                sys.exit(1)           
    else:     
        smbHW.shareAnalyze(to_analyze, to_match)
    if options.csv:
       db.exportToCSV()
    print ("Hope you found something good mate!")
    










