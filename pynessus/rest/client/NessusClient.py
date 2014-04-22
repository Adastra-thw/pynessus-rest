# coding=utf-8
'''
Created on 19/03/2014

#Author: Adastra.
#twitter: @jdaanial

NessusClient.py

WorkerThread is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

WorkerThread is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Tortazo; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
'''

import requests
import json

#http://static.tenable.com/documentation/nessus_5.0_XMLRPC_protocol_guide.pdf
class NessusClient:
    '''
    NessusClient. Class to consume the REST services defined running in a instance of Nessus Scanner.
    '''

    def __init__(self, nessusServer, nessusPort, validateCert=False, initialSeqNumber=1):
        self.nessusServer = nessusServer
        self.nessusPort = nessusPort
        self.url='https://'+str(nessusServer)+':'+str(nessusPort)
        self.token = None
        self.headers = {}
        self.bodyRequest = {}
        self.seqNumber = initialSeqNumber
        self.validateCert = validateCert
        self.nessusFunctions = {'login':'/login',
                                'logout':'/logout',
                                'feed':'/feed',
                                'server_securesettings_list':'/server/securesettings/list',
                                'server_securesettings':'/server/securesettings',
                                'server_preferences_list':'/server/preferences/list',
                                'server_preferences':'/server/preferences',
                                'server_update':'/server/update',
                                'server_register':'/server/register',
                                'server_load':'/server/load',
                                'server_uuid':'/uuid',
                                'server_getcert':'/getcert',
                                'server_plugins_process':'/plugins/process',
                                'users_add':'/users/add',
                                'users_delete':'/users/delete',
                                'users_edit':'/users/edit',
                                'users_chpasswd':'/users/chpasswd',
                                'users_list':'/users/list',
                                'plugins_list':'/plugins/list',
                                'plugins_attributes_list':'/plugins/attributes/list',
                                'plugins_list_family':'/plugins/list/family',
                                'plugins_description':'/plugins/description',
                                'plugins_preferences':'/plugins/preferences',
                                'plugins_attributes_familySearch':'/plugins/attributes/familySearch',
                                'plugins_attributes_pluginSearch':'/plugins/attributes/pluginSearch',
                                'plugins_md5':'/plugins/md5',
                                'plugins_descriptions':'/plugins/descriptions',
                                'policy_preferences_list':'/preferences/list',
                                'policy_list':'/policy/list',
                                'policy_delete':'/policy/delete',
                                'policy_copy':'/policy/copy',
                                'policy_add':'/policy/add',
                                'policy_edit':'/policy/edit',
                                'policy_download':'/policy/download',
                                'policy_file_upload':'/file/upload',
                                'policy_file_policy_import':'/file/policy/import',
                                'scan_new':'/scan/new',
                                'scan_stop':'/scan/stop',
                                'scan_resume':'/scan/resume',
                                'scan_pause':'/scan/pause',
                                'scan_list':'/scan/list',
                                'scan_timezones':'/timezones',
                                'scan_template_new':'/scan/template/new',
                                'scan_template_edit':'/scan/template/edit',
                                'scan_template_delete':'/scan/template/delete',
                                'scan_template_launch':'/scan/template/launch',
                                'report_list':'/report/list',
                                'report_delete':'/report/delete',
                                'report_hosts':'/report/hosts',
                                'report2_hosts_plugin':'/report2/hosts/plugin',
                                'report2_hosts':'/report2/hosts',
                                'report_ports':'/report/ports',
                                'report2_ports':'/report2/ports',
                                'report_details':'/report/details',
                                'report2_details_plugin':'/report2/details/plugin',
                                'report2_details':'/report2/details',
                                'report_tags':'/report/tags',
                                'report_hasAuditTrail':'/report/hasAuditTrail',
                                'report_attributes_list':'/report/attributes/list',
                                'report_errors':'/report/errors',
                                'report_hasKB':'/report/hasKB',
                                'report_canDeleteItems':'/report/canDeleteItems',
                                'report2_deleteItem':'/report2/deleteItem',
                                'report_trail_details':'/report/trail-details',
                                'report2_vulnerabilities':'/report2/vulnerabilities',
                                'report_chapter_list':'/chapter/list',
                                'report_chapter':'/chapter',
                                'report_file_import':'/file/report/import',
                                'report_file_download':'/file/report/download',
                                'report_file_xslt_list':'/file/xslt/list',
                                'report_file_xslt':'/file/xslt',
                                'report_file_xslt_download':'/file/xslt/download'
                                }

    def constructParamsAndHeaders(self, headers={}, params={}, jsonFormat=True):
        if jsonFormat:
            self.body = {'seq' : self.seqNumber, 'json' : '1'}
        else:
            self.body = {'seq' : self.seqNumber, 'json' : '0'}
        if self.token is not None:
            #No authentication needed.
            self.headers={'Host': str(self.nessusServer)+':'+str(self.nessusPort),
                          'Content-type':'application/x-www-form-urlencoded',
                          'Cookie':'token='+self.token}
        else:
            self.headers={'Host': str(self.nessusServer)+':'+str(self.nessusPort),
                          'Content-type':'application/x-www-form-urlencoded'}
        self.body.update(params)
        self.headers.update(headers)

    def requestNessus(self, url, method="POST"):
        '''
        Perform a request to Nessus server using the data and headers received by parameter.
        This function automatically increments the sequence identifier for Nessus requests.
        '''
        if method == "GET":
            response = requests.get(url, data=self.body, headers=self.headers, verify=self.validateCert)
        else:
            response = requests.post(url, data=self.body, headers=self.headers, verify=self.validateCert)
        self.seqNumber += 1
        try:
            return json.loads(response.content)
        except ValueError:
            return response.content

    def login(self, nessusUser, nessusPassword, jsonFormat=True):
        '''
        Login with the Nessus server using the user and password specified.
        '''
        self.constructParamsAndHeaders(params={'login':nessusUser, 'password':nessusPassword}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['login'], method="POST")
        if content['reply']['status'] == 'OK':
            self.token = content['reply']['contents']['token']
        return content

    def logout(self, jsonFormat=True):
        '''
        Logout function to destroy a token created previously.
        Returns None if there's no token loaded in the class.
        '''
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['logout'])
        return content

    def feed(self, jsonFormat=True, method="POST"):
        '''
        Logout function to destroy a token created previously.
        Returns None if there's no token loaded in the class.
        '''
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['feed'], method=method)
        return content

    def securesettingsList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_securesettings_list'], method=method)
        return content

    def secureSettings(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_securesettings'], method=method)
        return content

    def serverPreferencesList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_preferences_list'], method=method)
        return content


    def serverPreferences(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_preferences'], method=method)
        return content

    def serverUpdate(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_update'], method=method)
        return content


    def serverRegister(self, nessusFeed, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'code':nessusFeed},jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_register'], method=method)
        return content

    def serverLoad(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_load'], method=method)
        return content

    def serverUuid(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_uuid'], method=method)
        return content

    def serverGetCert(self,jsonFormat=False, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_getcert'], method=method)
        return content

    def serverPluginsProcess(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['server_plugins_process'], method=method)
        return content

    def usersAdd(self,login, password, admin=False, jsonFormat=True, method="POST"):
        adminUser = 0
        if admin:
            adminUser = 1
        self.constructParamsAndHeaders(params={'login':login,
                                               'password':password,
                                               'admin':adminUser}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['users_add'], method=method)
        return content

    def usersDelete(self,login,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'login':login}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['users_delete'], method=method)
        return content

    def usersEdit(self,login, password, admin=False, jsonFormat=True, method="POST"):
        adminUser = 0
        if admin:
            adminUser = 1
        self.constructParamsAndHeaders(params={'login':login,
                                               'password':password,
                                               'admin':adminUser}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['users_edit'], method=method)
        return content

    def usersChpasswd(self,login,password,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'login':login,
                                               'password':password}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['users_chpasswd'], method=method)
        return content

    def usersList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['users_list'], method=method)
        return content

    def pluginsList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_list'], method=method)
        return content

    def pluginsAttributesList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_attributes_list'], method=method)
        return content

    def pluginsListFamily(self, pluginFamily, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'family':pluginFamily}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_list_family'], method=method)
        return content

    def pluginsDescription(self, fileNamePlugin, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'fname':fileNamePlugin}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_description'], method=method)
        return content

    def pluginsPreferences(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_preferences'], method=method)
        return content

    def pluginsAttributesFamilySearch(self, filter0Quality, filterSearchType, filter0Value, filter0Filter, jsonFormat=True, method="POST"):

        #filter.0.quality – Four values are allowed here: match, nmatch, eq, neq
        #filter.search_type – The types of search: or, and
        #filter.0.filter – A full list of plugin attributes can be obtained from the /plugins/attributes/list function.
        self.constructParamsAndHeaders(params={'filter.0.quality':filter0Quality,
                                               'filter.search_type':filterSearchType,
                                               'filter.0.value':filter0Value,
                                               'filter.0.filter':filter0Filter},
                                       jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_attributes_familySearch'], method=method)
        return content

    def pluginsAttributesPluginSearch(self,filter0Quality,filterSearchType,filter0Value,filter0Filter,family,jsonFormat=True, method="POST"):
        #Same as pluginsAttributesFamilySearch.

        self.constructParamsAndHeaders(params={'filter.0.quality':filter0Quality,
                                               'filter.search_type':filterSearchType,
                                               'filter.0.value':filter0Value,
                                               'filter.0.filter':filter0Filter,
                                               'family':family}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_attributes_pluginSearch'], method=method)
        return content

    def pluginsMd5(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_md5'], method=method)
        return content

    def pluginsDescriptions(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['plugins_descriptions'], method=method)
        return content

    def policyPreferencesList(self,jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_preferences_list'], method=method)
        return content


    def policyList(self, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_list'], method=method)
        return content

    def policyDelete(self, policyId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'policy_id':policyId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_delete'], method=method)
        return content

    def policyCopy(self, policyId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'policy_id':policyId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_copy'], method=method)
        return content

    def policyAdd(self, policyData, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(headers=policyData , jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_copy'], method=method)
        return content

    def policyEdit(self, policyData, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(headers=policyData , jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_edit'], method=method)
        return content

    def policyDownload(self, policyId):
        self.constructParamsAndHeaders(jsonFormat=False)
        response = requests.get(self.url+self.nessusFunctions['policy_download']+'?policy_id='+str(policyId), data=self.body, headers=self.headers, verify=self.validateCert)
        self.seqNumber += 1
        return response.content

    def policyFileUpload(self, fileName, contents, jsonFormat=True, method="POST"):
        '''
        Perform a request to Nessus server using the data and headers received by parameter.
        This function automatically increments the sequence identifier for Nessus requests.
        '''
        self.headers['Content-Disposition'] = 'form-data; name="Filedata"; filename="'+fileName+'"'
        self.headers['Content-Type'] = 'application/octet-stream;multipart/form-data;'
        self.body = contents
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        if method == "GET":
            response = requests.get(self.url+self.nessusFunctions['policy_file_upload'], data=self.body, headers=self.headers, verify=self.validateCert)
        elif method == "POST":
            response = requests.post(self.url+self.nessusFunctions['policy_file_upload'], data=self.body, headers=self.headers, verify=self.validateCert)
        self.seqNumber += 1
        if jsonFormat:
            try:
                return json.loads(response.content)
            except ValueError:
                return response.content
        else:
            return response.content



    def policyFilePolicyImport(self, fileNessusName, jsonFormat=True):
        self.constructParamsAndHeaders(params={'file':fileNessusName}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_file_policy_import'])
        return content

    def policyFilePolicyImport(self, fileNessusName, jsonFormat=True):
        self.constructParamsAndHeaders(params={'file':fileNessusName}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['policy_file_policy_import'])
        return content

    def scanNew(self, target, policyId, scanName, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'target':str(target),
                                               'policy_id':str(policyId),
                                               'scan_name':str(scanName)}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_new'], method=method)
        return content

    def scanStop(self, scanUuid, jsonFormat=True):
        self.constructParamsAndHeaders(params={'scan_uuid':str(scanUuid)}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_stop'])
        return content

    def scanPause(self, scanUuid, jsonFormat=True):
        self.constructParamsAndHeaders(params={'scan_uuid':str(scanUuid)}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_pause'])
        return content

    def scanResume(self, scanUuid, jsonFormat=True):
        self.constructParamsAndHeaders(params={'scan_uuid':str(scanUuid)}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_resume'])
        return content

    def scanList(self, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_list'], method=method)
        return content

    def scanTimeZones(self, jsonFormat=True):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_timezones'])
        return content

    def scanTemplateNew(self, policyId, target, templateName, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'template_name':str(templateName),
                                               'policy_id':str(policyId),
                                               'target':str(target)}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_template_new'], method=method)
        return content


    def scanTemplateEdit(self, template, templateName, policyId, target, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'template':template,
                                               'template_name':templateName,
                                               'policy_id':policyId,
                                               'target':target} , jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_template_edit'], method=method)
        return content

    def scanTemplateDelete(self, template, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'template':template} , jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_template_delete'], method=method)
        return content

    def scanTemplateLaunch(self, template, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'template':template} , jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['scan_template_launch'], method=method)
        return content

    def reportList(self, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_list'], method=method)
        return content

    def reportDelete(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_delete'], method=method)
        return content

    def reportHosts(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_hosts'], method=method)
        return content

    def report2HostsPlugin(self, reportUuid, severity, pluginId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'severity':severity,
                                               'plugin_id':pluginId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_hosts_plugin'], method=method)
        return content

    def report2Hosts(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_hosts'], method=method)
        return content

    def reportPorts(self, reportUuid, hostname, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_ports'], method=method)
        return content

    def report2Ports(self, reportUuid, hostname, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_ports'], method=method)
        return content

    def reportDetails(self, reportUuid, hostname, port, protocol, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname,
                                               'port':port,
                                               'protocol':protocol}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_details'], method=method)
        return content

    def report2DetailsPlugin(self, reportUuid, hostname, port, protocol, severity, pluginId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname,
                                               'port':port,
                                               'protocol':protocol,
                                               'severity':severity,
                                               'plugin_id':pluginId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_details_plugin'], method=method)
        return content

    def report2Details(self, reportUuid, hostname, port, protocol, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname,
                                               'port':port,
                                               'protocol':protocol}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_details_plugin'], method=method)
        return content

    def reportTags(self, reportUuid, hostname, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_tags'], method=method)
        return content

    def reportHasAuditTrail(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_hasAuditTrail'], method=method)
        return content

    def reportAttributesList(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_attributes_list'], method=method)
        return content

    def reportErrors(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_errors'], method=method)
        return content

    def reportHasKB(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_hasKB'], method=method)
        return content

    def reportCanDeleteItems(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_canDeleteItems'], method=method)
        return content

    def reportCanDeleteItems(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_canDeleteItems'], method=method)
        return content


    def report2DeleteItem(self, reportUuid, hostname, port, pluginId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname,
                                               'port':port,
                                               'plugin_id':pluginId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_deleteItem'], method=method)
        return content

    def reportTrailDetails(self, reportUuid, hostname, pluginId, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'hostname':hostname,
                                               'plugin_id':pluginId}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_trail_details'], method=method)
        return content

    def report2Vulnerabilities(self, reportUuid, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report2_vulnerabilities'], method=method)
        return content

    def reportChapterList(self, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_chapter_list'], method=method)
        return content

    def reportChapter(self, reportUuid, chapters, format, token, v1=False, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'chapters':chapters,
                                               'format':format,
                                               'token':token,
                                               'v1':v1}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_chapter'], method=method)
        return content

    def reportFileDownload(self, reportUuid, v1=False, v2=True, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'v1':v1,
                                               'v2':v2}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_chapter'], method=method)
        return content

    def reportFileImport(self, fileName, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'file':fileName}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_file_import'], method=method)
        return content


    def reportFileXsltList(self, fileName, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_file_xslt_list'], method=method)
        return content

    def reportFileXslt(self, reportUuid, xslt, token, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'report':reportUuid,
                                               'xslt':xslt,
                                               'token':token}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_file_xslt'], method=method)
        return content

    def reportFileXsltDownload(self, fileName, jsonFormat=True, method="POST"):
        self.constructParamsAndHeaders(params={'fileName':fileName}, jsonFormat=jsonFormat)
        content = self.requestNessus(self.url+self.nessusFunctions['report_file_xslt_download'], method=method)
        return content

'''
n = NessusClient('127.0.0.1', '8834')
content = n.login('adastra', 'peraspera')
print content
print "\n"
print "\n"
content = n.feed()
print content
print "\n"
print "\n"
content = n.securesettingsList()
print content
print "\n"
print "\n"
content = n.secureSettings()
print content
print "\n"
print "\n"
content = n.logout()
print content
print "\n"
print "\n"
'''