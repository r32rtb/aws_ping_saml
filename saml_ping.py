#!/usr/bin/python3.7

from __future__ import print_function
from builtins import input
import base64
import boto3
from collections import namedtuple
import configparser
import getpass
import getopt
import json
import os
import sys
import requests
import lxml.html
import xml.etree.ElementTree as ET
from os.path import expanduser
from dateutil import tz
import yaml
import re
from threading import Thread
import argparse


class SamlConnector:
    
    def __init__(self, ssl_verification, region):
        self.user = None
        self.password = None
        self.ssl_verification = ssl_verification
        self.session = requests.Session()
        #Specify a ca-bundle if MITM Proxy in play
        #self.cafile = 'ca-bundle.crt'
        self.path = os.path.dirname(os.path.abspath(__file__))
        self.region = region

    def __del__(self):
        self.logout()

    def logout(self):
        self.user = None
        self.password = None
        self.session = None
        #self.alias_file.close()


    def find(self, d, tag):
        if tag in d:
            yield d[tag]
        for k, v in d.items():
            if isinstance(v, dict):
                for i in find(v, tag):
                    yield i

    def logon_info(self):
        print ("Username:", "")
        self.user = input()
        self.password = str(getpass.getpass())
        #Update if MFA in play
        #self.mfatoken = getpass.getpass("SafeNet TokenCode:")
        return(self.user, self.password)
        #return(self.user, self.password, self.mfatoken)

    def get_saml(self, url, partner, username, passwords):
        self.r = self.session.get(url + '/idp/startSSO.ping', params={'PartnerSpId': partner}, verify=self.path + "/" + self.cafile)
        self.r.raise_for_status()
        root = lxml.html.fromstring(self.r.text)
        for password in passwords:
            action = root.find('.//form').get('action')
            adapter_id = root.find(".//form/input[@name='pf.adapterId']").get('value')
            self.r = self.session.post(url + action, data={
                                   'pf.username': username,
                                   'pf.pass': password,
                                   'pf.adapterId': adapter_id
                             })
            self.r.raise_for_status()
            root = lxml.html.fromstring(self.r.text)
            #print(self.r.text)
            ping_error = root.find(".//div[@class='ping-error']")
            #print(ping_error)
            if ping_error is not None:
                break
        
        if ping_error is not None:
            return ('Failed')

        SAML = namedtuple('SAML', ['url', 'name', 'assertion'])
        return SAML(url=root.find('.//form').get('action'),
                    name=root.find('.//form/input').get('name'),
                    assertion=root.find('.//form/input').get('value'))

    def get_roles(self, assertion, duration):
        def resolve_aws_alias(role, principal, aws_dict):
            session = boto3.session.Session(region_name=self.region)
            sts = session.client('sts')
            saml = sts.assume_role_with_saml(RoleArn=role,
                                             PrincipalArn=principal,
                                             SAMLAssertion=assertion)
            iam = session.client('iam',
                                  aws_access_key_id=saml['Credentials']['AccessKeyId'],
                                  aws_secret_access_key=saml['Credentials']['SecretAccessKey'],
                                  aws_session_token=saml['Credentials']['SessionToken'])
            try:
                response = iam.list_account_aliases()
                account_alias = response['AccountAliases'][0]
                aws_dict[role.split(':')[4]] = account_alias
            except:
                sts = session.client('sts',
                                     aws_access_key_id=saml['Credentials']['AccessKeyId'],
                                     aws_secret_access_key=saml['Credentials']['SecretAccessKey'],
                                     aws_session_token=saml['Credentials']['SessionToken'])
                account_id = sts.get_caller_identity().get('Account')
                account_alias = '{}'.format(account_id)
                aws_dict[role.split(':')[4]] = '{}'.format(account_id)
            
            return account_alias

        awsroles = []
        root = ET.fromstring(base64.b64decode(assertion))
        for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
            if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
                for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                    awsroles.append(saml2attributevalue.text)
        
        for awsrole in awsroles:
            chunks = awsrole.split(',')
            if'saml-provider' in chunks[0]:
                newawsrole = chunks[1] + ',' + chunks[0]
                index = awsroles.index(awsrole)
                awsroles.insert(index, newawsrole)
                awsroles.remove(awsrole)
        
        print ("")
        threads = []
        aws_id_alias = {}
        if len(awsroles) > 1:
            seen_aws_accounts = []
            for awsrole in awsroles:
                if str(re.split(':',awsrole.split(',')[0],5)[4]) in seen_aws_accounts:
                    continue
                seen_aws_accounts.append(str(re.split(':',awsrole.split(',')[0],5)[4]))
                role = awsrole.split(',')[0]
                principal = awsrole.split(',')[1]
                t = Thread(target=resolve_aws_alias, args=(role, principal, aws_id_alias))
                t.start()
                threads.append(t)

            for t in threads:
                t.join()
            
            i = 0
            print ("Please choose the role you would like to assume:")
            for awsrole in awsroles:
                aws_account = str(re.split(':',awsrole.split(',')[0],5)[4])
                account_alias = aws_id_alias[aws_account]
                print ('[', i, ']: ', account_alias, ' ', awsrole.split(',')[0])
                i += 1

            print ("Selection: ")
            selectedroleindex = input()
            # Basic sanity check of input
            if int(selectedroleindex) > (len(awsroles) - 1):
                print ('You selected an invalid role index, please try again')
                sys.exit(0)
        
            role_arn = awsroles[int(selectedroleindex)].split(',')[0]
            principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
        else:
            role_arn = awsroles[0].split(',')[0]
            principal_arn = awsroles[0].split(',')[1]
        
        # Use the assertion to get an AWS STS token using Assume Role with SAML with internal CA Bundle
        sts = boto3.client('sts', verify=self.path + "/" + self.cafile)
        token = sts.response = sts.assume_role_with_saml(
            RoleArn=role_arn,
            PrincipalArn=principal_arn,
            SAMLAssertion=assertion,
            DurationSeconds=duration
        )
            
        credentials = token['Credentials']
        return credentials

    def set_creds(self, credentials, aws_config_file, aws_profile, output_format, region):
        # Write the AWS STS token into the AWS credential file
        home = expanduser("~")
        filename = home + aws_config_file
        
        # Read in the existing config file
        config = configparser.RawConfigParser()
        config.read(filename)
        
        # Put the credentials into the default section 
        #         # the default credentials
        if not config.has_section(aws_profile):
            config.add_section(aws_profile)
        
        config.set(aws_profile, 'output', output_format)
        config.set(aws_profile, 'region', region)
        config.set(aws_profile, 'aws_access_key_id', credentials['AccessKeyId'])
        config.set(aws_profile, 'aws_secret_access_key', credentials['SecretAccessKey'])
        config.set(aws_profile, 'aws_session_token', credentials['SessionToken'])
        
        # Write the updated config file
        with open(filename, 'w+') as configfile:
            config.write(configfile)
        
        from_zone = tz.tzutc()
        to_zone = tz.tzlocal()
        #expirationutc = format(credentials['Expiration'])
        expirationlz = credentials['Expiration'].astimezone(to_zone)
        
        # Give the user some basic info as to what has just happened
        print ('\n\n----------------------------------------------------------------')
        print ('Your new access key pair has been stored in the AWS configuration file {0} under the {1}.'.format(filename, aws_profile))
        print ('Note that it will expire at {0} utc or {1} localtime.'.format(credentials['Expiration'], expirationlz))
        #print 'Note that it will expire at {0} localtime.'.format(expirationlz)
        print ('After this time, you may safely rerun this script to refresh your access key pair.')
        print ('To use this credential, call the AWS CLI with the --profile option (e.g. aws ec2 describe-instances).')
        print ('----------------------------------------------------------------\n\n')

def main(argv=None):
    url = 'https://idp.your_pingfederate.com:9031'
    idp_partner = 'urn:amazon:webservices'
    region = 'us-east-1'
    aws_config_file = '/.aws/credentials'
    aws_profile = 'default'
    ssl_verification = True 
    username = None
    password = None
    mfatoken = None
    role = None
    as_json = False
    output_format = 'json'

    if not argv:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description='Some Company AWS SAML Role Selector')
    parser.add_argument(
        '-d',
        dest='duration',
        help='Session Token duration in seconds default 14400 or 4 hour, max=14400',
        default='14400',
        type=int
    )
    parser.add_argument(
        '-p',
        dest='aws_profile',
        help='Credential profile name where the key, secret and sts token can be called from with the -profile argument',
        default='default',
        type=str
    )
    args = parser.parse_args(argv)
    duration = args.duration
    aws_profile = args.aws_profile
    if not 60 <= duration <= 14400:
        print('Duration must be between 60 and 14400 seconds, using default of 14400')
        duration = 14400
    
    saml_connect = SamlConnector(ssl_verification, region)

    #(username, password, mfatoken) = saml_connect.logon_info()
    (username, password) = saml_connect.logon_info()
    #saml = saml_connect.get_saml(url, idp_partner, username, [ password, mfatoken ])
    saml = saml_connect.get_saml(url, idp_partner, username, [ password ])
    while saml is 'Failed':
        print('Invalid Credentials, Try Again!')
        saml_connect = SamlConnector(ssl_verification, region)
        #(username, password, mfatoken) = saml_connect.logon_info()
        (username, password) = saml_connect.logon_info()
        #saml = saml_connect.get_saml(url, idp_partner, username, [ password, mfatoken ])
        saml = saml_connect.get_saml(url, idp_partner, username, [ password ])

    credentials = saml_connect.get_roles(saml. assertion, duration)
    saml_connect.set_creds(credentials, aws_config_file, aws_profile, output_format, region)



if __name__ == "__main__":
    main()