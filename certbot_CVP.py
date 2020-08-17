from jsonrpclib import Server
import ssl
import base64
from cvplibrary import CVPGlobalVariables, GlobalVariableNames, os


ssl._create_default_https_context = ssl._create_unverified_context


class cvpApis(object):
    def __init__(self):
        socket.setdefaulttimeout(3)
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            self.server = cvp.Cvp(host=CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP, ssl=True, port=443, tmpDir='')
            self.server.authenticate(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME, CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD)

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
        url = 'https://{}:{}@{}/command-api'.format(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_USERNAME, CVPGlobalVariables.getValue(GlobalVariableNames.CVP_PASSWORD, ipAddress)
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
cert = '''-----BEGIN CERTIFICATE-----
Your Cert Goes Here.
-----END CERTIFICATE-----'''
cert_encoded = cert.encode('base64','strict')
cert_stripped = cert_encoded.replace('\n','')

key = '''-----BEGIN RSA PRIVATE KEY-----
Your Key Goes Here.
-----END RSA PRIVATE KEY-----'''
key_encoded = key.encode('base64','strict')
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


### Rest of script
def main():
    targetDevice = cvpApis().getDevice(CVPGlobalVariables.getValue(GlobalVariableNames.CVP_MAC))

                                                                                

    #Removing existing certificates from /tmp.                                                                         
    eapi(targetDevice.ipAddress, ['enable', 'bash timeout 10 rm -rf /tmp/cert*'])

                                                                                

    #Uploading new certificate.
    eapi(targetDevice.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certcer.tmp'.format(cert_stripped), 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])

                                                                                

    #Uploading new key.
    eapi(targetDevice.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/certcer.tmp'.format(cert_stripped), 'bash timeout 2 base64 -d /tmp/certcer.tmp > /tmp/cert.cer'])

                                                                                

    #Uploading intermediate certificate.
    eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/cert.intermediate.tmp'.format(intermediate_stripped), 'bash timeout 2 base64 -d /tmp/cert.intermediate.tmp > /tmp/cert.intermediate'])


                                                                                
    #Uploading CA certificate.
    eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/cert.ca.tmp'.format(ca_cert_stripped), 'bash timeout 2 base64 -d /tmp/cert.ca.tmp > /tmp/cert.ca'])

                                                                                
                                                                                
    #Move certificates from /tmp to EOS.
    eapi(device.ipAddress, ['enable', 'bash timeout 2 echo "{}" > /tmp/cert.ca.tmp'.format(ca_cert_stripped), 'bash timeout 2 base64 -d /tmp/cert.ca.tmp > /tmp/cert.ca'])

                                                                                
                                                                                
    #Removing certificates from /tmp.                                                                         
    eapi(targetDevice.ipAddress, ['enable', 'bash timeout 10 rm -rf /tmp/cert*'])

if __name__ == "__main__":
  main()
