#!/usr/bin/env python
#
# Copyright (c) 2020, Arista Networks, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
#   Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
#   Neither the name of Arista Networks nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ARISTA NETWORKS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#



from datetime import datetime
from getpass import getpass
from jsonrpclib import Server
import argparse, base64, cvp, json, socket, ssl, sys, urllib3



ssl._create_default_https_context = ssl._create_unverified_context



#
# Define command line options for optparse
#
usage = 'usage: %prog [options]'

# Define command line options for argparse
ap = argparse.ArgumentParser()
ap.add_argument(
    "-c",
    "--cvphostname",
    dest="cvphostname",
    action="store",
    required=True,
    help="CVP host name FQDN or IP",
)

ap.add_argument(
    "-u",
    "--cvpusername",
    dest="cvpusername",
    action="store",
    required=True,
    help="CVP username",
)

ap.add_argument(
    "-p",
    "--cvppassword",
    dest="cvppassword",
    action="store",
    required=False,
    default="",
    help="CVP password",
)

ap.add_argument(
    "-d",
    "--debug",
    dest="debug",
    action="store_true",
    help="If debug is set, nothing will actually be sent to CVP and proposed configs are written to terminal",
    default=False,
)

ap.add_argument(
    "-t",
    "--trace",
    dest="trace",
    action="store_true",
    help="If trace is set, alongside actual changes to CVP configlets, there will be trace messages to terminal",
    default=False,
)

opts = ap.parse_args()

## If no password is passed then ask for it.
if opts.cvppassword == '':
    password =  getpass.getpass(prompt='Password: ', stream=None)
else:
    password = opts.cvppassword

#
# Assign command line options to variables and assign static variables.
#

host = opts.cvphostname
user = opts.cvpusername
debug = opts.debug
trace = opts.trace



class bcolors:
    NORMAL = '\033[0m'
    BOLD = '\033[1m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'



class cvpApis(object):
    def __init__(self):
        socket.setdefaulttimeout(3)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            self.server = cvp.Cvp(host=host, ssl=True, port=443, tmpDir='')
            self.server.authenticate(user, password)

        except cvpServices.CvpError as error:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}ERROR{}: {}.\n'.format(timestamp, bcolors.ERROR, bcolors.NORMAL, error))
            sys.exit(1)

    def getDevice(self, deviceMacAddress, provisioned=True):
        return self.server.getDevice(deviceMacAddress, provisioned)

    def getDevices(self, provisioned=True):
        return self.server.getDevices()



def eapi(ipAddress, cmds):
    try:
        socket.setdefaulttimeout(3)
        url = 'https://{}:{}@{}/command-api'.format(user, password, ipAddress)
        switch = Server(url)
        response = switch.runCmds( 1, cmds )

    except socket.timeout:
        if trace:
            sys.stderr.write('Error in {} eAPI call to {}.\n'.format(cmds, ipAddress))

        return None

    except err as e:
        if trace:
            sys.stderr.write('Error in {} eAPI call to {}.\n'.format(cmds, ipAddress))

        return None

    else:
        if trace:
            sys.stderr.write('{} eAPI call to {} successful.\n'.format(cmds, ipAddress))

        return response



### Certificate Info - expected to be PEM format.
# Replace with your own cert and key.
cert = """\
-----BEGIN CERTIFICATE-----
Your Cert Goes Here.
-----END CERTIFICATE-----"""
cert_encoded = cert.encode('base64','strict')
cert_stripped = cert_encoded.replace('\n','')



cert_key = """\
-----BEGIN RSA PRIVATE KEY-----
Your Key Goes Here.
-----END RSA PRIVATE KEY-----"""
key_encoded = cert_key.encode('base64','strict')
key_stripped = key_encoded.replace('\n','')



ca_cert = '''-----BEGIN CERTIFICATE-----
Your CA Certificate Goes Here.
-----END CERTIFICATE-----'''
ca_cert_encoded = ca_cert.encode('base64','strict')
ca_cert_stripped = ca_cert_encoded.replace('\n','')



intermediate = '''-----BEGIN CERTIFICATE-----
Your Intermediate Certificate Goes Here.
-----END CERTIFICATE-----'''
intermediate_encoded = intermediate.encode('base64','strict')
intermediate_stripped = intermediate_encoded.replace('\n','')



def main():
    sys.stderr.write('\n\n\n\n\n')



    timestamp = datetime.now().replace(microsecond=0)
    sys.stderr.write('{} {}INFO{}: Getting CVP device inventory...'.format(timestamp, bcolors.BOLD, bcolors.NORMAL))

    '''
    #test against a SINGLE targetDevice

    temp = cvpApis().getDevice('44:4c:a8:b8:84:f0')
    targetDevices = []
    targetDevices.append(temp)
    '''

    # OR apply to all targetDevice(s)
    targetDevices = cvpApis().getDevices()



    for device in targetDevices:
        sys.stderr.write('\n\n\n\n\n===========================================================\n')
        sys.stderr.write('Processing device {}.\n'.format(device.fqdn))



        try:
            if trace:
                sys.stderr.write('Removing existing certificates from /tmp.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 10 rm -rf /tmp/cert*'])



            if trace:
                sys.stderr.write('Uploading new certificate.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certcer.tmp'.format(cert_stripped), 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])
                                   


            if trace:
                sys.stderr.write('Uploading new key.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certkey.tmp'.format(key_stripped), 'bash timeout 2 base64 -d /tmp/certkey.tmp > /tmp/cert.key'])

            
            
            if trace:
                sys.stderr.write('Uploading intermediate certificate.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/cert.intermediate.tmp'.format(intermediate_stripped), 'bash timeout 2 base64 -d /tmp/cert.intermediate.tmp > /tmp/cert.intermediate'])


                        
            if trace:
                sys.stderr.write('Uploading CA certificate.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/cert.ca.tmp'.format(ca_cert_stripped), 'bash timeout 2 base64 -d /tmp/cert.ca.tmp > /tmp/cert.ca'])


            
            if trace:
                sys.stderr.write('Move certificates from /tmp to EOS.\n')

            eapi(device.ipAddress, ['enable', 'copy file:/tmp/cert.cer certificate:{}'.format(cert_name), 'copy file:/tmp/cert.key sslkey:{}'.format(key_name), 'copy file:/tmp/cert.intermediate certificate:{}'.format(intermediate_name), 'copy file:/tmp/cert.ca certificate:'.format(ca_name)])

            
            
            if trace:
                sys.stderr.write('Applying new certificate.\n')
          
            eapi(device.ipAddress, ['enable', 'configure', 'management security', 'ssl profile https-secure', 'certificate cert key certkey', 'cipher-list HIGH:!NULL:!MD5:!aNULL'])
            eapi(device.ipAddress, ['enable', 'configure', 'management api http-commands', 'protocol https ssl profile https-secure'])

            
            
            if trace:
                sys.stderr.write('Removing certificates from /tmp.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 10 rm -rf /tmp/cert*'])

        except:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}WARNING{}: Failure on Device {}.'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, device.fqdn))


        else:
            timestamp = datetime.now().replace(microsecond=0)
            sys.stderr.write('{} {}INFO{}: Success on Device {}.'.format(timestamp, bcolors.WARNING, bcolors.NORMAL, device.fqdn))



    sys.stderr.write('\n===========================================================\n\n\n\n\n')



if __name__ == "__main__":
    main()
