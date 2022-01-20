#!/usr/bin/env python3

import ldap
import argparse
import getpass
import sys
import re
import string
from datetime import datetime
import base64
import csv



class LDAPSearchResult(object):
    """A helper class to work with raw search results
    Copied from here: https://www.packtpub.com/books/content/configuring-and-securing-python-ldap-applications-part-2
    """

    dn = ''

    def __init__(self, entry_tuple):
        (dn, attrs) = entry_tuple
        if dn:
            self.dn = dn
        else:
            return

        self.attrs = ldap.cidict.cidict(attrs)

    def get_attributes(self):
        return self.attrs

    def has_attribute(self, attr_name):
        return attr_name in self.attrs

    def get_attr_values(self, key):
        return self.attrs[key]

    def get_attr_names(self):
        return self.attrs.keys()

    def get_dn(self):
        return self.dn

    def get_print_value(self, value):
        isprintable = False
        try:
            dec_value = value.decode()
            isprintable = dec_value.isprintable()
            if isprintable:
                value = dec_value
        except UnicodeDecodeError:
            pass
        if not isprintable:
            value = base64.b64encode(value).decode()

        return value

    def pretty_print(self):
        attrs = self.attrs.keys()
        final_list = []
        try: 
            values = self.get_attr_values('dNSHostName')
        except Exception as e:
            values = self.get_attr_values('cn')

        return self.get_print_value(values[0]).strip('\n')



class LDAPSession(object):
    def __init__(self, dc_ip='', username='', password='', domain=''):

        if dc_ip:
            self.dc_ip = dc_ip
        else:
            self.get_set_DC_IP(domain)

        self.username = username
        self.password = password
        self.domain = domain

        self.con = self.initializeConnection()
        self.domainBase = ''
        self.is_binded = False

    def initializeConnection(self):
        

        con = ldap.initialize('ldap://{}'.format(self.dc_ip))
        con.set_option(ldap.OPT_REFERRALS, 0)
        return con

    def unbind(self):
        self.con.unbind()
        self.is_binded = False

     

    def getDefaultNamingContext(self):
        try:
            newCon = ldap.initialize('ldap://{}'.format(self.dc_ip))
            newCon.simple_bind_s('', '')
            res = newCon.search_s("", ldap.SCOPE_BASE, '(objectClass=*)')
            rootDSE = res[0][1]
        except ldap.LDAPError as e:
            print("[!] Error retrieving the root DSE")
            print("[!] {}".format(e))
            sys.exit(1)

        if 'defaultNamingContext' not in rootDSE:
            print("[!] No defaultNamingContext found!")
            sys.exit(1)

        defaultNamingContext = rootDSE['defaultNamingContext'][0].decode()

        self.domainBase = defaultNamingContext
        newCon.unbind()
        return defaultNamingContext

    def do_bind(self):
        try:
            self.con.simple_bind_s(self.username, self.password)
            self.is_binded = True
            return True
        except ldap.INVALID_CREDENTIALS:
            print("[!] Error: invalid credentials")
            sys.exit(1)
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

    def whoami(self):
        try:
            current_dn = self.con.whoami_s()
        except ldap.LDAPError as e:
            print("[!] {}".format(e))
            sys.exit(1)

        return current_dn

    def do_ldap_query(self, base_dn, subtree, objectFilter, attrs, page_size=1000):
        """
        actually perform the ldap query, with paging
        copied from another LDAP search script I found: https://github.com/CroweCybersecurity/ad-ldap-enum
        found this script well after i'd written most of this one. oh well
        """
        more_pages = True
        cookie = None

        ldap_control = ldap.controls.SimplePagedResultsControl(True, size=page_size, cookie='')

        allResults = []

        while more_pages:
            msgid = self.con.search_ext(base_dn, subtree, objectFilter, attrs, serverctrls=[ldap_control])
            result_type, rawResults, message_id, server_controls = self.con.result3(msgid)

            allResults += rawResults

            # Get the page control and get the cookie from the control.
            page_controls = [c for c in server_controls if
                             c.controlType == ldap.controls.SimplePagedResultsControl.controlType]

            if page_controls:
                cookie = page_controls[0].cookie

            if not cookie:
                more_pages = False
            else:
                ldap_control.cookie = cookie

        return allResults

    def get_search_results(self, results):
        # takes raw results and returns a list of helper objects
        res = []
        arr = []
        if type(results) == tuple and len(results) == 2:
            (code, arr) = results
        elif type(results) == list:
            arr = results

        if len(results) == 0:
            return res

        for item in arr:
            resitem = LDAPSearchResult(item)
            if resitem.dn:  # hack to workaround "blank" results
                res.append(resitem)

        return res

    def getFunctionalityLevel(self):
        objectFilter = '(objectclass=*)'
        attrs = ['domainFunctionality', 'forestFunctionality', 'domainControllerFunctionality']
        try:
            # rawFunctionality = self.do_ldap_query('', ldap.SCOPE_BASE, objectFilter, attrs)
            rawData = self.con.search_s('', ldap.SCOPE_BASE, "(objectclass=*)", attrs)
            functionalityLevels = rawData[0][1]
        except Error as e:
            print("[!] Error retrieving functionality level")
            print("[!] {}".format(e))
            sys.exit(1)

        return functionalityLevels



    def getAllComputers(self, attrs=''):
        if not attrs:
            attrs = ['cn', 'dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']

        objectFilter = '(objectClass=Computer)'
        base_dn = self.domainBase

        try:
            rawComputers = self.do_ldap_query(base_dn, ldap.SCOPE_SUBTREE, objectFilter, attrs)
        except ldap.LDAPError as e:
            print("[!] Error retrieving computers")
            print("[!] {}".format(e))
            sys.exit(1)

        return self.get_search_results(rawComputers), attrs

 


def prettyPrintResults(results, showDN=False):
    final_list = []
    for result in results:

        final_list.append(result.pretty_print())
        
    return final_list    





def printFunctionalityLevels(levels):
    for name, level in levels.items():
        print("[+]\t {}: {}".format(name, FUNCTIONALITYLEVELS[level[0]]))


def run(args):
    startTime = datetime.now().strftime("%Y%m%d-%H:%M:%S")
    if not args.username:
        
        print("[+] No username provided. I'm not going to try the anonymous bind.")
        sys.exit(1)
    else:
        username = args.username

    if args.username and not args.password:
        password = getpass.getpass("Password for {}: ".format(args.username))
    elif args.password:
        password = args.password


    ldapSession = LDAPSession(dc_ip=args.dc_ip, username=username, password=password, domain=args.domain)

    print("[+] Using Domain Controller at: {}".format(ldapSession.dc_ip))

    print("[+] Getting defaultNamingContext from Root DSE")
    print("[+]\tFound: {}".format(ldapSession.getDefaultNamingContext()))


    print("[+] Attempting bind")
    ldapSession.do_bind()

    if ldapSession.is_binded:
        print("[+]\t...success! Binded as: ")
        print("[+]\t {}".format(ldapSession.whoami()))

    attrs = ''
    attrs = ['dNSHostName', 'cn']



    
    print("\n[+] Enumerating all AD computers")
    allComputers, searchAttrs = ldapSession.getAllComputers(attrs=attrs)
    if not allComputers:
        bye(ldapSession)
    print("[+]\tFound {} computers: \n".format(len(allComputers)))
    
    
    finallist = prettyPrintResults(allComputers)

    return finallist    
    bye(ldapSession)


def isValidDN(testdn):
    # super lazy regex way to see if what they entered is a DN
    dnRegex = re.compile('(DC=[^,"]+)+')
    return dnRegex.search(testdn)


def selectResult(results):
    print("[+] Found {} results:\n".format(len(results)))
    for number, result in enumerate(results):
        print("{}: {}".format(number, result.dn))
    print("")
    response = input("Which DN do you want to use? : ")
    return results[int(response)]


def bye(ldapSession):
    ldapSession.unbind()



