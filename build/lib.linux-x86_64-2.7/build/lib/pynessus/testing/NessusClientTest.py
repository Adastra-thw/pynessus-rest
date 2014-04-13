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

if __name__ == "__main__":
    client = NessusClient('127.0.0.1','8834')
    client.login('adastra','peraspera')

    '''converter = NessusConverter(client.pluginsList())
    data = converter.pluginsToStructure()
    print data
    print "\n\n"
    client.
    '''
    print client.feed(method="POST")
    client.user
    # filter0Quality, filterSearchType, filter0Value, filter0Filter
    #pprint(client.pluginsAttributesFamilySearch('match','or','modicon','description'))
    #print(client.pluginsAttributesPluginSearch('match','or','modicon','description','FTP'))

    #pprint(client.policyList())
    #contents = client.policyDownload(1)
    #print contents
    #print client.policyFileUpload("tested.nessus", contents)
    #print client.policyFilePolicyImport("tested.nessus")
    #print client.scanNew("127.0.0.1",'1','testScan')
    #print client.scanStop('ec665c9e-ce24-336b-acb4-e2b199fac1800854abce5c111a8d')
    #{u'reply': {u'status': u'OK', u'contents': {u'template': {u'owner': u'adastra', u'readablename': u'MIERDATEMPLATE', u'target': u'127.0.0.1', u'name': u'template-c3b2cb22-9d31-0b61-99d2-37fd517299c61ef6026c2dbe5fa3', u'policy_id': u'1'}}, u'seq': u'2'}}

    #print  client.scanTemplateNew('1','127.0.0.1', 'NewTemplate')
    #print  client.scanTemplateEdit('template-14aec035-cf4b-864f-a178-22d4bb4903f37f2f6f05e532ac33' , 'NewName', '1','127.0.0.1')
    #print  client.scanTemplateDelete('template-14aec035-cf4b-864f-a178-22d4bb4903f37f2f6f05e532ac33' , 'NewName', '1','127.0.0.1')

    #print client.scanTemplateLaunch('NewTemplate')
    #print client.scanTemplateDelete('NewTemplate')

    #print  client.scanTemplateDelete('template-c3b2cb22-9d31-0b61-99d2-37fd517299c61ef6026c2dbe5fa3')

    #print client.scanTemplateLaunch(nessusConverter.nessusStructure.nessusScanTemplate.name)
    #print client.scanTemplateDelete(nessusConverter.nessusStructure.nessusScanTemplate.name)

    #print client.scanTemplateLaunch('template-6b6adcdb-a346-38c2-ab58-723406b83ba851b7adf1aa8d0487')


    #print client.reportList()
    #print client.reportDelete("9365feeb-0733-0c65-fd25-19c167d1dc40ec635cdb84a34fb0")
    #print client.reportHosts("eae24e38-4b92-e7ea-2c96-ce5a47b7fcbdf7018c7248ffbc21")
    #print client.report2HostsPlugin("e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736", '1', '22194')
    #print client.report2Hosts("e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736")
    #print client.reportPorts('e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736', '192.168.1.226')
    #print client.report2Ports('e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736', '192.168.1.226')
    #print client.reportDetails('e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736', '192.168.1.222', '139', 'tcp')
    #print client.report2DetailsPlugin("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb", '127.0.0.1','80')
    #print client.reportHosts("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb")

    #print client.reportTags("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb", '127.0.0.1', jsonFormat=True)
    #print client.reportHasAuditTrail("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb")
    #pprint(client.reportAttributesList("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb"))
    #pprint(client.report2Vulnerabilities("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb"))

    nessusConverter = NessusConverter(client.policyList(method="POST"))
    nessusConverter.policyStructureToStructure()
    for policy in nessusConverter.nessusStructure.nessusPolicies:
        print policy.policyId +' - '+ policy.policyName

    nessusConverter = NessusConverter(client.reportList())
    nessusConverter.reportToStructure()
    for report in nessusConverter.nessusStructure.reportList:
        print report.name +' - '+ report.status

    '''
    nessusConverter = NessusConverter(client.reportAttributesList("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb"))
    nessusConverter.reportAttributesToStructure()
    for reportAttribute in nessusConverter.nessusStructure.nessusReportAttributes:
        print reportAttribute.type +' - '+ reportAttribute.regex

    nessusConverter = NessusConverter(client.reportTags("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb", '127.0.0.1', jsonFormat=True))
    nessusConverter.tagToNessusStructure()
    for tag in nessusConverter.nessusStructure.nessusTags:
        print tag.name +' - '+ tag.value
    '''



