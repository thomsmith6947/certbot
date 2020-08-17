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
        ssl._create_default_https_context = ssl._create_unverified_context
        switch = Server(url)
        response = switch.runCmds( 1, cmds )

    except socket.timeout:
        if trace:
            sys.stderr.write('Error in eAPI call to {}.\n'.format(ipAddress))

        return None

    except err as e:
        if trace:
            sys.stderr.write('Error in eAPI call to {}.\n'.format(ipAddress))

        return None

    else:
        return response



### Certificate Info - expected to be PEM format.
# Replace with your own cert and key.
cert = """\
-----BEGIN CERTIFICATE-----
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
-----END CERTIFICATE-----"""
cert_encoded = cert.encode('base64','strict')
cert_stripped = cert_encoded.replace('\n','')



cert_key = """\
-----BEGIN RSA PRIVATE KEY-----
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
MIIGJTCCBA2gAwIBAgIBAjANBgkqhkiG9w0BAQUFADCBsjELMAkGA1UEBhMCRlIx
-----END RSA PRIVATE KEY-----"""
key_encoded = cert_key.encode('base64','strict')
key_stripped = key_encoded.replace('\n','')



Last login: Tue Aug 11 23:24:41 on ttys002

The default interactive shell is now zsh.
To update your account to use zsh, please run `chsh -s /bin/zsh`.
For more details, please visit https://support.apple.com/kb/HT208050.
Thomass-MacBook-Pro:~ thomsmith$ cd Downloads
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
Temporary_Registration_7357GM.pdf
Temporary_Registration_BK74120.pdf
VMware-Remote-Console-11.0.1-15716515.dmg
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
convertGenerated2StaticV3.txt
convertGenerated2StaticV4.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
home-mortgage-calculator.xlsx
inventory-6-22-2020_15_38_19_178.csv
inventory-6-22-2020_15_55_32_241.csv
inventory.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
loan-amortization-schedule.xlsx
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
viewer.jnlp(10.20.30.224@0@1581204003913)
wifi
~$loan-amortization-schedule.xlsx
Thomass-MacBook-Pro:Downloads thomsmith$ rm inventory*
Thomass-MacBook-Pro:Downloads thomsmith$ cd Downloads
-bash: cd: Downloads: Not a directory
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
Temporary_Registration_7357GM.pdf
Temporary_Registration_BK74120.pdf
VMware-Remote-Console-11.0.1-15716515.dmg
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
convertGenerated2StaticV3.txt
convertGenerated2StaticV4.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
home-mortgage-calculator.xlsx
lab.local-config-2-11-2020_20_24_33_915.json
licenses
loan-amortization-schedule.xlsx
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
viewer.jnlp(10.20.30.224@0@1581204003913)
wifi
~$loan-amortization-schedule.xlsx
Thomass-MacBook-Pro:Downloads thomsmith$ rm convert*
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
Temporary_Registration_7357GM.pdf
Temporary_Registration_BK74120.pdf
VMware-Remote-Console-11.0.1-15716515.dmg
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
home-mortgage-calculator.xlsx
lab.local-config-2-11-2020_20_24_33_915.json
licenses
loan-amortization-schedule.xlsx
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
viewer.jnlp(10.20.30.224@0@1581204003913)
wifi
~$loan-amortization-schedule.xlsx
Thomass-MacBook-Pro:Downloads thomsmith$ rm *.xlsx
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
Temporary_Registration_7357GM.pdf
Temporary_Registration_BK74120.pdf
VMware-Remote-Console-11.0.1-15716515.dmg
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
viewer.jnlp(10.20.30.224@0@1581204003913)
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm viewer*
Thomass-MacBook-Pro:Downloads thomsmith$ rm VMware-Remote-Console-11.0.1-15716515.dmg
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
Temporary_Registration_7357GM.pdf
Temporary_Registration_BK74120.pdf
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ -rm Temporary*
-bash: -rm: command not found
Thomass-MacBook-Pro:Downloads thomsmith$ rm Temporary*
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
README.md
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm README.md
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
NYSSA_Voucher_for_Club_1696.pdf
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm NYSSA*
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
Loan Estimate (Thomas Smith).pdf
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm Loan*
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
cEOS-lab-4.22.3M.tar.xz
configletDataFile 2.txt
configletDataFile.txt
cv
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm cEOS-lab-4.22.3M.tar.xz
Thomass-MacBook-Pro:Downloads thomsmith$ rm cv
rm: cv: is a directory
Thomass-MacBook-Pro:Downloads thomsmith$ rm -rf cv
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
ExportedConfigletsData (1).zip
ExportedConfigletsData.zip
Foster Smith agreement for dock co-ownership 5 23 2020.docx
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
configletDataFile 2.txt
configletDataFile.txt
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
meeting-94147652358.ics
meeting-95386468363.ics
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ rm Exported*
Thomass-MacBook-Pro:Downloads thomsmith$ rm meeting*
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
Foster Smith agreement for dock co-ownership 5 23 2020.docx
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
configletDataFile 2.txt
configletDataFile.txt
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ cd Downloads
-bash: cd: Downloads: Not a directory
Thomass-MacBook-Pro:Downloads thomsmith$ ls
CVP-2019.1.0-offline-demo.tgz
CVP-change-controls-table-20200804_215345.csv
Campus Leafs-config-2-11-2020_20_28_59_514.json
CloudVision update - Sales Call - Oct 1st, 2018.pptx
CloudVisionPortal2020.1.2ReleaseNotesv1.0.pdf
CvEosConversionV2.txt
Desktop
Downloads
EOS-4.22.3M.swi
EOS-4.23.1F.swi
Foster Smith agreement for dock co-ownership 5 23 2020.docx
TY 2019-1099+Consolidated-9568 (1).pdf
TY 2019-1099+Consolidated-9568.pdf
aigConfigCleanup.txt
configletDataFile 2.txt
configletDataFile.txt
demo-provisioning.csv
demo-provisioning1.csv
global-csv-export.1.csv
lab.local-config-2-11-2020_20_24_33_915.json
licenses
networks.csv
nypConfigCleanup.py
nypEvpn.py
server.py
tk2demo.csv
vEOS-lab.swi
vEOS64-lab-4.22.6M.swi
wifi
Thomass-MacBook-Pro:Downloads thomsmith$ pwd
/Users/thomsmith/Downloads
Thomass-MacBook-Pro:Downloads thomsmith$ cd /Downloads
-bash: cd: /Downloads: No such file or directory
Thomass-MacBook-Pro:Downloads thomsmith$ scp root@10.20.30.181:/home/cvp/convertGenerated2StaticV5.py .
root@10.20.30.181's password: 
convertGenerated2StaticV5.py                  100%   18KB 125.2KB/s   00:00    
Thomass-MacBook-Pro:Downloads thomsmith$ ssh root@10.20.30.181
root@10.20.30.181's password: 
Last login: Fri Aug 14 19:13:01 2020 from 10.212.134.200
[root@cvpappl1 ~]# cd /home/cvp
[root@cvpappl1 cvp]# ls
aigCert.py                     disneyDeploy.py
aigConfigCleanup.py            disneyDeploy.py.BAK
convertGenerated2Static.py     disneyDeployV2.py
convertGenerated2StaticV2.py   flashCleanup.py
convertGenerated2StaticV3.py   inputTest
convertGenerated2StaticV4.py   ipamApis.py
convertGenerated2StaticV5.py   ipam-ui-v1.2.0-1.noarch.rpm
customerDeployV2.py            nypEvpn.py
CVEOSConversion.py             onboardDevice.py
CvEosConversionV2.py           rbcDeploy.py
deleteAllTasksAndSnapshots.py  switches.csv
demoEvpnV2.py                  thom.tar
demoEvpnV3.py
[root@cvpappl1 cvp]# vi certbot.py

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
                sys.stderr.write('Removing existing certificate.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 10 rm -rf /tmp/cert*'])



            if trace:
                sys.stderr.write('Uploading new certificate.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certcer.tmp'.format(cert_stripped), 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])



            if trace:
                sys.stderr.write('Uploading new key.\n')

            eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certkey.tmp'.format(key_stripped), 'bash timeout 2 base64 -d /tmp/certkey.tmp > /tmp/cert.key'])



            if trace:
                sys.stderr.write('Applying new certificate.\n')

            eapi(device.ipAddress, ['enable', 'copy file:/tmp/cert.cer certificate:cert', 'copy file:/tmp/cert.key sslkey:certkey'])
            eapi(device.ipAddress, ['enable', 'configure', 'management security', 'ssl profile https-secure', 'certificate cert key certkey', 'cipher-list HIGH:!NULL:!MD5:!aNULL'])
            eapi(device.ipAddress, ['enable', 'configure', 'management api http-commands', 'protocol https ssl profile https-secure'])



            if trace:
                sys.stderr.write('Removing old certificate.\n')

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
