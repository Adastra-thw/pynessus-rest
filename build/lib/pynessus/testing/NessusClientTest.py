# coding=utf-8
'''
Created on 19/03/2014

#Author: Adastra.
#twitter: @jdaanial

NessusClientTest.py

NessusClientTest is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

NessusClientTest is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pynessus-rest; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
'''

from pynessus.rest.client.NessusClient import NessusClient
from pynessus.rest.data.NessusStructure import NessusStructure, NessusConverter

from pprint import pprint
from bs4 import BeautifulSoup
if __name__ == "__main__":
    client = NessusClient('127.0.0.1','8834')
    client.login('adastra','peraspera')

    '''converter = NessusConverter(client.pluginsList())
    data = converter.pluginsToStructure()
    print data
    print "\n\n"
    client.
    '''
    # filter0Quality, filterSearchType, filter0Value, filter0Filter
    pprint(client.pluginsAttributesFamilySearch('match','or','modicon','description'))
    #print(client.pluginsAttributesPluginSearch('match','or','modicon','description','FTP'))

    pprint(client.policyList())
    #contents = client.policyDownload(1)
    #print contents
    #print client.policyFileUpload("tested.nessus", contents)
    #print client.policyFilePolicyImport("tested.nessus")
    #print client.scanNew("127.0.0.1",'1','testScan')
    #print client.scanStop('ec665c9e-ce24-336b-acb4-e2b199fac1800854abce5c111a8d')
    #scanList =  client.scanList(jsonFormat=True)
    #print  client.scanTimeZones()


