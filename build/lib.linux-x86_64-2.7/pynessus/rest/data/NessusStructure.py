# coding=utf-8
'''
Created on 19/03/2014

#Author: Adastra.
#twitter: @jdaanial

NessusStructure.py

NessusStructure is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 2 of the License.

NessusStructure is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with pynessus-rest; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
'''

from bs4 import BeautifulSoup
import json
class NessusConverter():
    '''
    Class to convert the data structures from Nessus to pynessus-rest data-model objects.
    '''
    def __init__(self, data):
        self.data = data
        self.nessusStructure = NessusStructure()
        if isinstance(self.data, str):
            self.bs = BeautifulSoup(data,"lxml")


    def pluginsToStructure(self):
        '''
        Plugins to Structure.
        '''

        if self.data['reply']['contents'].has_key('pluginfamilylist'):
            if self.data['reply']['contents']['pluginfamilylist'].has_key('family'):
                self.pluginStructure = self.data['reply']['contents']['pluginfamilylist']['family']
                for structure in self.pluginStructure:
                    plugin = NessusFamily()
                    plugin.familyName = structure['familyname']
                    plugin.familyMembers = structure['numfamilymembers']
                    self.nessusStructure.plugins.append(plugin)

    def feedToStructure(self):
        nessusFeed = NessusFeed()
        if self.data['reply']['contents'].has_key('feed'):
            nessusFeed.feed = self.data['reply']['contents']['feed']
        if self.data['reply']['contents'].has_key('reportEmail'):
            nessusFeed.reportEmail = self.data['reply']['contents']['reportEmail']
        if self.data['reply']['contents'].has_key('tags'):
            nessusFeed.tags = self.data['reply']['contents']['tags']
        if self.data['reply']['contents'].has_key('msp'):
            nessusFeed.msp = self.data['reply']['contents']['msp']
        if self.data['reply']['contents'].has_key('multi_scanner'):
            nessusFeed.multiScanner = self.data['reply']['contents']['multi_scanner']
        if self.data['reply']['contents'].has_key('plugin_rules'):
            nessusFeed.pluginRules = self.data['reply']['contents']['plugin_rules']
        if self.data['reply']['contents'].has_key('expiration'):
            nessusFeed.expiration = self.data['reply']['contents']['expiration']
        if self.data['reply']['contents'].has_key('nessus_ui_version'):
            nessusFeed.uiVersion = self.data['reply']['contents']['nessus_ui_version']
        if self.data['reply']['contents'].has_key('nessus_type'):
            nessusFeed.nessusType = self.data['reply']['contents']['nessus_type']
        if self.data['reply']['contents'].has_key('diff'):
            nessusFeed.diff = self.data['reply']['contents']['diff']
        if self.data['reply']['contents'].has_key('expiration_time'):
            nessusFeed.expirationTime = self.data['reply']['contents']['expiration_time']
        if self.data['reply']['contents'].has_key('loaded_plugin_set'):
            nessusFeed.loadedPluginSet = self.data['reply']['contents']['loaded_plugin_set']
        if self.data['reply']['contents'].has_key('server_version'):
            nessusFeed.serverVersion = self.data['reply']['contents']['server_version']
        if self.data['reply']['contents'].has_key('web_server_version'):
            nessusFeed.webServerVersion = self.data['reply']['contents']['web_server_version']
        self.nessusStructure.feed = nessusFeed

    def secureSettingsListToStructure(self):
        nessusSecureSettings = NessusSecureSettings()
        if self.data['reply']['contents'].has_key('securesettings'):
            if self.data['reply']['contents']['securesettings'].has_key('proxysettings'):
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('proxy_password'):
                    nessusSecureSettings.proxyPassword = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_password']
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('proxy_port'):
                    nessusSecureSettings.proxyPort = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_port']
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('custom_host'):
                    nessusSecureSettings.customHost = self.data['reply']['contents']['securesettings']['proxysettings']['custom_host']
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('proxy_username'):
                    nessusSecureSettings.proxyUserName = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_username']
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('user_agent'):
                    nessusSecureSettings.userAgent = self.data['reply']['contents']['securesettings']['proxysettings']['user_agent']
                if self.data['reply']['contents']['securesettings']['proxysettings'].has_key('proxy'):
                    nessusSecureSettings.proxy = self.data['reply']['contents']['securesettings']['proxysettings']['proxy']
                self.nessusStructure.secureSettings = nessusSecureSettings
            if self.data['reply']['contents'].has_key('preferences'):
                nessusSecureSettings.preferences = self.data['reply']['contents']['preferences']


    def serverPreferencesListToStructure(self):
        if self.data['reply']['contents'].has_key('serverpreferences'):
            self.nessusStructure.serverPreferences = self.data['reply']['contents']['serverpreferences']

    def serverUpdateToStructure(self):
       if self.data['reply']['contents'].has_key('update'):
           self.nessusStructure.serverUpdate = self.data['reply']['contents']['update']

    def serverRegisterToStructure(self):
        if self.data['reply']['contents'].has_key('registration'):
            self.nessusStructure.serverRegistration = self.data['reply']['contents']['registration']

    def serverLoadToStructure(self):
        nessusServerLoad = NessusServerLoad()
        if self.data['reply']['contents'].has_key('load'):
            if self.data['reply']['contents']['load'].has_key('num_scans'):
                nessusServerLoad.numScans = self.data['reply']['contents']['load']['num_scans']
            if self.data['reply']['contents']['load'].has_key('num_sessions'):
                nessusServerLoad.numSessions = self.data['reply']['contents']['load']['num_sessions']
            if self.data['reply']['contents']['load'].has_key('num_hosts'):
                nessusServerLoad.numHosts = self.data['reply']['contents']['load']['num_hosts']
            if self.data['reply']['contents']['load'].has_key('num_tcp_sessions'):
                nessusServerLoad.numTcpSessions = self.data['reply']['contents']['load']['num_tcp_sessions']
            if self.data['reply']['contents']['load'].has_key('loadavg'):
                nessusServerLoad.loadAvg = self.data['reply']['contents']['load']['loadavg']
        if self.data['reply']['contents'].has_key('platform'):
            nessusServerLoad.platform = self.data['reply']['contents']['platform']
        self.nessusStructure.serverLoad = nessusServerLoad

    def serverUuidToStructure(self):
        if self.data['reply']['contents'].has_key('uuid'):
            self.nessusStructure.uuid = self.data['reply']['contents']['uuid']

    def serverGetCertToStructure(self):
        if self.data is not None:
            self.nessusStructure.serverCert = self.data

    def serverPluginsProcessToStructure(self):
         if self.data['reply']['contents'].has_key('plugins_processing'):
            self.nessusStructure.pluginsProcess = self.data['reply']['contents']['plugins_processing']

    def userToStructure(self):
        if self.data['reply']['contents'].has_key('users'):
            for user in self.data['reply']['contents']['users']['user']:
                nessusUser = NessusUser()
                if user.has_key('name'):
                    nessusUser.name = user['name']
                if user.has_key('admin'):
                    nessusUser.admin = user['admin']
                if user.has_key('idx'):
                    nessusUser.idx = user['idx']
                if user.has_key('lastlogin'):
                    nessusUser.lastLogin = user['lastlogin']
                self.nessusStructure.nessusUsers.append(nessusUser)
        if self.data['reply']['contents'].has_key('user'):
            nessusUser = NessusUser()
            if self.data['reply']['contents']['user'].has_key('name'):
                nessusUser.name = self.data['reply']['contents']['user']['name']
            if self.data['reply']['contents']['user'].has_key('admin'):
                nessusUser.admin = self.data['reply']['contents']['user']['admin']
            if self.data['reply']['contents']['user'].has_key('idx'):
                nessusUser.idx = self.data['reply']['contents']['user']['idx']
            if self.data['reply']['contents']['user'].has_key('lastlogin'):
                nessusUser.lastLogin = self.data['reply']['contents']['user']['lastlogin']
            self.nessusStructure.nessusUser = nessusUser

    def pluginsListToStructure(self):
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('family'):
                 for family in self.data['reply']['contents']['pluginfamilylist']['family']:
                     nessusPlugin = NessusFamily()
                     if family.has_key('numfamilymembers'):
                         nessusPlugin.familyMembers = family['numfamilymembers']
                     if family.has_key('familyname'):
                         nessusPlugin.familyName = family['familyname']
                     self.nessusStructure.pluginsList.append(nessusPlugin)

    def pluginsAttributesToStructure(self):
        if self.data['reply']['contents'].has_key('pluginsattributes'):
            if self.data['reply']['contents']['pluginsattributes'].has_key('attribute'):
                for attribute in self.data['reply']['contents']['pluginsattributes']['attribute']:
                    pluginAttribute = NessusPluginAttribute()
                    if attribute.has_key('name'):
                        pluginAttribute.name = attribute['name']
                    if attribute.has_key('readable_name'):
                        pluginAttribute.readableName = attribute['readable_name']


                    if attribute.has_key('control'):
                        control = NessusPluginAttributeControl()
                        if attribute['control'].has_key('readable_regex'):
                            control.readableRegex = attribute['control']['readable_regex']
                        if attribute['control'].has_key('regex'):
                            control.regex = attribute['control']['regex']
                        if attribute['control'].has_key('type'):
                            control.type = attribute['control']['type']
                        if attribute['control'].has_key('list'):
                            control.list = attribute['control']['list']['entry']
                        pluginAttribute.control = control
                    if attribute.has_key('operators'):
                        pluginAttribute.operators = attribute['operators']['operator']
                    self.nessusStructure.pluginsAttributes.append(pluginAttribute)

    def pluginListFamilyToStructure(self):
        if self.data['reply']['contents'].has_key('pluginlist'):
            if self.data['reply']['contents']['pluginlist'].has_key('plugin'):
                for plugin in self.data['reply']['contents']['pluginlist']['plugin']:
                    pluginListFamily = NessusPlugin()
                    if plugin.has_key('pluginfamily'):
                        pluginListFamily.pluginFamily = plugin['pluginfamily']
                    if plugin.has_key('pluginfilename'):
                        pluginListFamily.pluginFileName = plugin['pluginfilename']
                    if plugin.has_key('pluginid'):
                        pluginListFamily.pluginId = plugin['pluginid']
                    if plugin.has_key('pluginname'):
                        pluginListFamily.pluginName = plugin['pluginname']
                    self.nessusStructure.pluginsListFamily.append(pluginListFamily)

    def pluginsDescriptionToStructure(self):
        if self.data['reply']['contents'].has_key('plugindescription'):
            pluginsDescription = NessusPluginsDescription()
            if self.data['reply']['contents']['plugindescription'].has_key('pluginfamily'):
                pluginsDescription.pluginFamily = self.data['reply']['contents']['plugindescription']['pluginfamily']
            if self.data['reply']['contents']['plugindescription'].has_key('pluginid'):
                pluginsDescription.pluginId = self.data['reply']['contents']['plugindescription']['pluginid']
            if self.data['reply']['contents']['plugindescription'].has_key('pluginname'):
                pluginsDescription.pluginName = self.data['reply']['contents']['plugindescription']['pluginname']


            if self.data['reply']['contents']['plugindescription'].has_key('pluginattributes'):
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('bid'):
                    pluginsDescription.bid = self.data['reply']['contents']['plugindescription']['pluginattributes']['bid']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cpe'):
                    pluginsDescription.cpe = self.data['reply']['contents']['plugindescription']['pluginattributes']['cpe']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cve'):
                    pluginsDescription.cve = self.data['reply']['contents']['plugindescription']['pluginattributes']['cve']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cvss_base_score'):
                    pluginsDescription.cvssBaseScore = self.data['reply']['contents']['plugindescription']['pluginattributes']['cvss_base_score']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cvss_temporal_score'):
                    pluginsDescription.cvssTemporalScore = self.data['reply']['contents']['plugindescription']['pluginattributes']['cvss_temporal_score']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cvss_temporal_vector'):
                    pluginsDescription.cvssTemporalVector = self.data['reply']['contents']['plugindescription']['pluginattributes']['cvss_temporal_vector']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('cvss_vector'):
                    pluginsDescription.cvssVector = self.data['reply']['contents']['plugindescription']['pluginattributes']['cvss_vector']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('description'):
                    pluginsDescription.description = self.data['reply']['contents']['plugindescription']['pluginattributes']['description']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('exploit_available'):
                    pluginsDescription.exploitAvailable = self.data['reply']['contents']['plugindescription']['pluginattributes']['exploit_available']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('exploitability_ease'):
                    pluginsDescription.exploitabilityEase = self.data['reply']['contents']['plugindescription']['pluginattributes']['exploitability_ease']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('patch_publication_date'):
                    pluginsDescription.pluginPatchDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['patch_publication_date']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('plugin_modification_date'):
                    pluginsDescription.pluginModificationDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['plugin_modification_date']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('plugin_publication_date'):
                    pluginsDescription.pluginPublicationDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['plugin_publication_date']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('plugin_type'):
                    pluginsDescription.pluginType = self.data['reply']['contents']['plugindescription']['pluginattributes']['plugin_type']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('plugin_version'):
                    pluginsDescription.pluginVector = self.data['reply']['contents']['plugindescription']['pluginattributes']['plugin_version']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('risk_factor'):
                    pluginsDescription.riskFactor = self.data['reply']['contents']['plugindescription']['pluginattributes']['risk_factor']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('see_also'):
                    pluginsDescription.seeAlso = self.data['reply']['contents']['plugindescription']['pluginattributes']['see_also']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('solution'):
                    pluginsDescription.solution = self.data['reply']['contents']['plugindescription']['pluginattributes']['solution']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('stig_severity'):
                    pluginsDescription.stigSeverity = self.data['reply']['contents']['plugindescription']['pluginattributes']['stig_severity']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('synopsis'):
                    pluginsDescription.synopsis = self.data['reply']['contents']['plugindescription']['pluginattributes']['synopsis']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('vuln_publication_date'):
                    pluginsDescription.vulnPublicationDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['vuln_publication_date']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('xref'):
                    pluginsDescription.xref = self.data['reply']['contents']['plugindescription']['pluginattributes']['xref']
                self.nessusStructure.pluginsDescription = pluginsDescription

    def pluginsPreferencesToStructure(self):
        if self.data['reply']['contents'].has_key('pluginspreferences'):
            if self.data['reply']['contents']['pluginspreferences'].has_key('item'):
                for item in self.data['reply']['contents']['pluginspreferences']['item']:
                    pluginPreference = NessusPluginPreference()
                    if self.data['reply']['contents']['pluginspreferences']['item'].has_key('fullname'):
                        pluginPreference.fullName = self.data['reply']['contents']['pluginspreferences']['item']['fullname']
                    if self.data['reply']['contents']['pluginspreferences']['item'].has_key('pluginname'):
                        pluginPreference.pluginName = self.data['reply']['contents']['pluginspreferences']['item']['pluginname']
                    if self.data['reply']['contents']['pluginspreferences']['item'].has_key('preferencename'):
                        pluginPreference.preferenceName = self.data['reply']['contents']['pluginspreferences']['item']['preferencename']
                    if self.data['reply']['contents']['pluginspreferences']['item'].has_key('preferencetype'):
                        pluginPreference.preferenceType = self.data['reply']['contents']['pluginspreferences']['item']['preferencetype']
                    if self.data['reply']['contents']['pluginspreferences']['item'].has_key('preferencevalues'):
                        pluginPreference.preferenceValues = self.data['reply']['contents']['pluginspreferences']['item']['preferencevalues']
                    self.nessusStructure.pluginsPreferences = pluginPreference

    def pluginsAttributeFamilySearchToStructure(self): #Test: client.pluginsAttributesFamilySearch('match','and','modicon','description')
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('family'):
                 self.nessusStructure.pluginsAttributeFamilySearch = self.data['reply']['contents']['pluginfamilylist']['family']


    def pluginsAttributePluginSearchToStructure(self): #Test: client.pluginsAttributesPluginSearch('match','or','modicon','description','FTP')
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('plugin'):
                 pluginFamily = NessusPlugin()
                 if self.data['reply']['contents']['pluginfamilylist']['plugin'].has_key('pluginfamily'):
                     pluginFamily.pluginFamily = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginfamily']
                 if self.data['reply']['contents']['pluginfamilylist']['plugin'].has_key('pluginfilename'):
                     pluginFamily.pluginFileName = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginfilename']
                 if self.data['reply']['contents']['pluginfamilylist']['plugin'].has_key('pluginid'):
                     pluginFamily.pluginId = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginid']
                 if self.data['reply']['contents']['pluginfamilylist']['plugin'].has_key('pluginname'):
                     pluginFamily.pluginName = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginname']
                 self.nessusStructure.pluginsAttributePluginSearch = pluginFamily

    def md5StructureToStructure(self):
         if self.data['reply']['contents'].has_key('entries'):
             if self.data['reply']['contents']['entries'].has_key('entry'):
                 for entry in self.data['reply']['contents']['entries']['entry']:
                     md5Entry = NessusMd5Entry()
                     if entry.has_key('filename'):
                         md5Entry.fileName = entry['filename']
                     if entry.has_key('md5'):
                         md5Entry.md5 = entry['md5']
                     self.nessusStructure.md5Structure.append(md5Entry)

    def pluginsDescriptionsToStructure(self):
        if self.data['reply']['contents'].has_key('pluginslist') and self.data['reply']['contents']['pluginslist'].has_key('plugindescription'):
            for pluginDesc in self.data['reply']['contents']['pluginslist']['plugindescription']:
                pluginsDescription = NessusPluginsDescription()
                if pluginDesc.has_key('pluginattributes'):
                    if pluginDesc['pluginattributes'].has_key('bid'):
                        pluginsDescription.bid = pluginDesc['pluginattributes']['bid']
                    if pluginDesc['pluginattributes'].has_key('cpe'):
                        pluginsDescription.cpe = pluginDesc['pluginattributes']['cpe']
                    if pluginDesc['pluginattributes'].has_key('cve'):
                        pluginsDescription.cve = pluginDesc['pluginattributes']['cve']
                    if pluginDesc['pluginattributes'].has_key('cvss_base_score'):
                        pluginsDescription.cvssBaseScore = pluginDesc['pluginattributes']['cvss_base_score']
                    if pluginDesc['pluginattributes'].has_key('cvss_temporal_score'):
                        pluginsDescription.cvssTemporalScore = pluginDesc['pluginattributes']['cvss_temporal_score']
                    if pluginDesc['pluginattributes'].has_key('cvss_temporal_vector'):
                        pluginsDescription.cvssTemporalVector = pluginDesc['pluginattributes']['cvss_temporal_vector']
                    if pluginDesc['pluginattributes'].has_key('cvss_vector'):
                        pluginsDescription.cvssVector = pluginDesc['pluginattributes']['cvss_vector']
                    if pluginDesc['pluginattributes'].has_key('description'):
                        pluginsDescription.description = pluginDesc['pluginattributes']['descriptor']
                    if pluginDesc['pluginattributes'].has_key('exploit_available'):
                        pluginsDescription.exploitAvailable = pluginDesc['pluginattributes']['exploit_available']
                    if pluginDesc['pluginattributes'].has_key('exploitability_ease'):
                        pluginsDescription.exploitabilityEase = pluginDesc['pluginattributes']['exploitability_ease']
                    if pluginDesc['pluginattributes'].has_key('patch_publication_date'):
                        pluginsDescription.pluginPublicationDate = pluginDesc['pluginattributes']['patch_publication_date']
                    if pluginDesc['pluginattributes'].has_key('plugin_modification_date'):
                        pluginsDescription.pluginModificationDate = pluginDesc['pluginattributes']['plugin_modification_date']
                    if pluginDesc['pluginattributes'].has_key('plugin_publication_date'):
                        pluginsDescription.pluginPublicationDate = pluginDesc['pluginattributes']['plugin_publication_date']
                    if pluginDesc['pluginattributes'].has_key('plugin_type'):
                        pluginsDescription.pluginType = pluginDesc['pluginattributes']['plugin_type']
                    if pluginDesc['pluginattributes'].has_key('plugin_version'):
                        pluginsDescription.pluginVector = pluginDesc['pluginattributes']['plugin_version']
                    if pluginDesc['pluginattributes'].has_key('risk_factor'):
                        pluginsDescription.riskFactor = pluginDesc['pluginattributes']['risk_factor']
                    if pluginDesc['pluginattributes'].has_key('see_also'):
                        pluginsDescription.seeAlso =pluginDesc['pluginattributes']['see_also']
                    if pluginDesc['pluginattributes'].has_key('solution'):
                        pluginsDescription.solution = pluginDesc['pluginattributes']['solution']
                    if pluginDesc['pluginattributes'].has_key('stig_severity'):
                        pluginsDescription.stigSeverity = pluginDesc['pluginattributes']['stig_severity']
                    if pluginDesc['pluginattributes'].has_key('synopsis'):
                        pluginsDescription.synopsis = pluginDesc['pluginattributes']['synopsis']
                    if pluginDesc['pluginattributes'].has_key('vuln_publication_date'):
                        pluginsDescription.vulnPublicationDate = pluginDesc['pluginattributes']['vuln_publication_date']
                    if pluginDesc['pluginattributes'].has_key('vuln_publication_date'):
                        pluginsDescription.vulnPublicationDate = pluginDesc['pluginattributes']['vuln_publication_date']
                    if pluginDesc.has_key('xref'):
                        pluginsDescription.xref = pluginDesc['xref']
                    if pluginDesc.has_key('pluginfamily'):
                        pluginsDescription.pluginFamily = pluginDesc['pluginfamily']
                    if pluginDesc.has_key('pluginid'):
                        pluginsDescription.pluginId = pluginDesc['pluginid']
                    if pluginDesc.has_key('pluginname'):
                        pluginsDescription.pluginName = pluginDesc['pluginname']
                    self.nessusStructure.pluginsDescriptions.append(pluginsDescription)


    def serverPolicyPreferenceToStructure(self):
        if self.data['reply']['contents'].has_key('serverpreferences'):
            if self.data['reply']['contents']['serverpreferences'].has_key('preference'):
                for preference in self.data['reply']['contents']['serverpreferences']['preference']:
                    policyPreference = NessusPolicyPreference()
                    if preference.has_key('name'):
                        policyPreference.name = preference['name']
                    if preference.has_key('value'):
                        policyPreference.value = preference['value']
                    self.nessusStructure.policyPreferences.append(policyPreference)



    def policyStructureToStructure(self):
        if self.data['reply']['contents'].has_key('policies'):
            if self.data['reply']['contents']['policies'].has_key('policy'):
                if isinstance(self.data['reply']['contents']['policies']['policy'], list):
                    for policy in self.data['reply']['contents']['policies']['policy']:
                        nessusPolicy = NessusPolicy()
                        if policy.has_key('policycontents'):
                            if policy['policycontents'].has_key('familyselection'):
                                if policy['policycontents']['familyselection'].has_key('familyitem'):
                                    for familyItem in policy['policycontents']['familyselection']['familyitem']:
                                        family = NessusFamily()
                                        if familyItem.has_key('familyname'):
                                            family.familyName = familyItem['familyname']
                                        if familyItem.has_key('status'):
                                            family.familyStatus = familyItem['status']
                                        nessusPolicy.policyFamilySelection.append(family)
                            if policy['policycontents'].has_key('individualpluginselection'):
                                if policy['policycontents']['individualpluginselection'].has_key('pluginitem'):
                                    for plugin in policy['policycontents']['individualpluginselection']['pluginitem']:
                                        nessusPlugin = NessusPlugin()
                                        if isinstance(plugin, unicode):
                                            nessusPlugin.pluginName = plugin
                                        else:
                                            if plugin.has_key('family'):
                                                nessusPlugin.pluginFamily = plugin['family']
                                            if plugin.has_key('pluginid'):
                                                nessusPlugin.pluginId = plugin['pluginid']
                                            if plugin.has_key('pluginname'):
                                                nessusPlugin.pluginName = plugin['pluginname']
                                            if plugin.has_key('status'):
                                                nessusPlugin.pluginStatus = plugin['status']
                                            nessusPolicy.individualPluginSelection.append(nessusPlugin)
                            if policy['policycontents'].has_key('policycomments'):
                                nessusPolicy.policyComments = policy['policycontents']['policycomments']
                            if policy['policycontents'].has_key('policycomments'):
                                nessusPolicy.policyComments = policy['policycontents']['policycomments']
                            if policy['policycontents'].has_key('preferences'):
                                if policy['policycontents']['preferences'].has_key('pluginspreferences'):
                                    for item in policy['policycontents']['preferences']['pluginspreferences']['item']:
                                        pluginPreference = NessusPluginPreference()
                                        if item.has_key('fullname'):
                                            pluginPreference.fullName = item['fullname']
                                        if item.has_key('pluginid'):
                                            pluginPreference.pluginId = item['pluginid']
                                        if item.has_key('pluginname'):
                                            pluginPreference.pluginName = item['pluginname']
                                        if item.has_key('preferencename'):
                                            pluginPreference.preferenceName = item['preferencename']
                                        if item.has_key('preferencetype'):
                                            pluginPreference.preferenceType = item['preferencetype']
                                        if item.has_key('preferencevalues'):
                                            pluginPreference.preferenceValues = item['preferencevalues']
                                        nessusPolicy.pluginPreferences.append(pluginPreference)
                            if policy['policycontents'].has_key('serverpreferences'):
                                if policy['policycontents']['serverpreferences'].has_key('preference'):
                                    for preference in policy['policycontents']['serverpreferences']['preference']:
                                        policyPreference = NessusPolicyPreference()
                                        if preference.has_key('name'):
                                            policyPreference.name = preference['name']
                                        if preference.has_key('value'):
                                            policyPreference.value = preference['value']
                                        nessusPolicy.pluginPreferences.append(policyPreference)

                            if policy.has_key('policyid'):
                                nessusPolicy.policyId = policy['policyid']

                            if policy.has_key('policyname'):
                                 nessusPolicy.policyName = policy['policyname']

                            if policy.has_key('policyowner'):
                                nessusPolicy.policyOwner = policy['policyowner']

                            if policy.has_key('visibility'):
                                nessusPolicy.policyVisibility =policy['visibility']
                        self.nessusStructure.nessusPolicies.append(nessusPolicy)
                else:
                    nessusPolicy = NessusPolicy()
                    policy = self.data['reply']['contents']['policies']['policy']
                    if policy['policycontents'].has_key('familyselection'):
                        if policy['policycontents']['familyselection'].has_key('familyitem'):
                            for familyItem in policy['policycontents']['familyselection']['familyitem']:
                                family = NessusFamily()
                                if familyItem.has_key('familyname'):
                                    family.familyName = familyItem['familyname']
                                if familyItem.has_key('status'):
                                    family.familyStatus = familyItem['status']
                                nessusPolicy.policyFamilySelection.append(family)
                        if policy['policycontents'].has_key('individualpluginselection'):
                            if policy['policycontents']['individualpluginselection'].has_key('pluginitem'):
                                for plugin in policy['policycontents']['individualpluginselection']['pluginitem']:
                                    nessusPlugin = NessusPlugin()
                                    if isinstance(plugin, unicode):
                                        nessusPlugin.pluginName = plugin
                                    else:
                                        if plugin.has_key('family'):
                                            nessusPlugin.pluginFamily = plugin['family']
                                        if plugin.has_key('pluginid'):
                                            nessusPlugin.pluginId = plugin['pluginid']
                                        if plugin.has_key('pluginname'):
                                            nessusPlugin.pluginName = plugin['pluginname']
                                        if plugin.has_key('status'):
                                            nessusPlugin.pluginStatus = plugin['status']
                                        nessusPolicy.individualPluginSelection.append(nessusPlugin)
                        if policy['policycontents'].has_key('policycomments'):
                            nessusPolicy.policyComments = policy['policycontents']['policycomments']
                        if policy['policycontents'].has_key('policycomments'):
                            nessusPolicy.policyComments = policy['policycontents']['policycomments']
                        if policy['policycontents'].has_key('preferences'):
                            if policy['policycontents']['preferences'].has_key('pluginspreferences'):
                                for item in policy['policycontents']['preferences']['pluginspreferences']['item']:
                                    pluginPreference = NessusPluginPreference()
                                    if item.has_key('fullname'):
                                        pluginPreference.fullName = item['fullname']
                                    if item.has_key('pluginid'):
                                        pluginPreference.pluginId = item['pluginid']
                                    if item.has_key('pluginname'):
                                        pluginPreference.pluginName = item['pluginname']
                                    if item.has_key('preferencename'):
                                        pluginPreference.preferenceName = item['preferencename']
                                    if item.has_key('preferencetype'):
                                        pluginPreference.preferenceType = item['preferencetype']
                                    if item.has_key('preferencevalues'):
                                        pluginPreference.preferenceValues = item['preferencevalues']
                                    nessusPolicy.pluginPreferences.append(pluginPreference)
                        if policy['policycontents'].has_key('serverpreferences'):
                            if policy['policycontents']['serverpreferences'].has_key('preference'):
                                for preference in policy['policycontents']['serverpreferences']['preference']:
                                    policyPreference = NessusPolicyPreference()
                                    if preference.has_key('name'):
                                        policyPreference.name = preference['name']
                                    if preference.has_key('value'):
                                        policyPreference.value = preference['value']
                                    nessusPolicy.pluginPreferences.append(policyPreference)

                        if policy.has_key('policyid'):
                            nessusPolicy.policyId = policy['policyid']

                        if policy.has_key('policyname'):
                            nessusPolicy.policyName = policy['policyname']

                        if policy.has_key('policyowner'):
                            nessusPolicy.policyOwner = policy['policyowner']

                        if policy.has_key('visibility'):
                            nessusPolicy.policyVisibility =policy['visibility']
                self.nessusStructure.nessusPolicies.append(nessusPolicy)

    def policyDeletedToStructure(self):
        if self.data['reply']['contents'].has_key('policy_id'):
            self.nessusStructure.policyDeleted = self.data['reply']['contents']['policy_id']

    def policyDownloadedToStructure(self):
        self.nessusStructure.policyDownloaded = self.data

    def fileUploadedToStructure(self):
        if self.data['reply']['contents'].has_key('fileuploaded'):
            self.nessusStructure.fileUploaded = self.data['reply']['contents']['fileuploaded']

    def scanToStructure(self):
        print self.data
        if self.data['reply']['contents'].has_key('scan'):
            nessusScan = NessusScan()
            if self.data['reply']['contents']['scan'].has_key('owner'):
                nessusScan.owner = self.data['reply']['contents']['scan']['owner']
            if self.data['reply']['contents']['scan'].has_key('scan_name'):
                nessusScan.scanName = self.data['reply']['contents']['scan']['scan_name']
            if self.data['reply']['contents']['scan'].has_key('start_time'):
                nessusScan.startTime = self.data['reply']['contents']['scan']['start_time']
            if self.data['reply']['contents']['scan'].has_key('uuid'):
                nessusScan.uuid = self.data['reply']['contents']['scan']['uuid']
            if self.data['reply']['contents']['scan'].has_key('readablename'):
                nessusScan.readableName = self.data['reply']['contents']['scan']['readablename']
            if self.data['reply']['contents']['scan'].has_key('status'):
                nessusScan.status = self.data['reply']['contents']['scan']['status']
            if self.data['reply']['contents']['scan'].has_key('completion_current'):
                nessusScan.completionCurrent = self.data['reply']['contents']['scan']['completion_current']
            if self.data['reply']['contents']['scan'].has_key('completion_total'):
                nessusScan.completionTotal = self.data['reply']['contents']['scan']['completion_total']
            self.nessusStructure.scan = nessusScan

    def scanListToStructure(self):
        '''if self.bs.status.text == 'OK':
            scans = self.bs.find_all("scan")
            for scan in scans:
                nessusScan = NessusScan()
                nessusScan.owner = scan.owner.text
                nessusScan.uuid = scan.uuid.text
                nessusScan.readableName = scan.readablename.text
                nessusScan.startTime = scan.start_time.text
                nessusScan.status = scan.status.text
                nessusScan.completionCurrent = scan.completion_current.text
                nessusScan.completionTotal = scan.completion_total.text

                policies = self.bs.find_all("policy")
                for policy in policies:
                    nessusPolicy = NessusPolicy()
                    nessusPolicy.policyId = policy.policyid.text
                    nessusPolicy.policyName = policy.policyname.text
                    nessusPolicy.policyOwner = policy.policyowner.text
                    nessusPolicy.policyVisibility = policy.visibility.text
                    nessusPolicy.policyComments = policy.policycomments.text
                    nessusScan.scanPolicies.append(nessusPolicy)
                self.nessusStructure.scanList.append(nessusScan)
        '''
        if self.data['reply']['contents'].has_key('scans'):
            if self.data['reply']['contents']['scans'].has_key('scanlist'):
                for scan in self.data['reply']['contents']['scans']['scanlist']['scan']:
                    if isinstance(scan, dict):
                        nessusScan = NessusScan()
                        if scan.has_key('status'):
                            nessusScan.status = scan['status']
                        if scan.has_key('readablename'):
                            nessusScan.readablename = scan['readablename']
                        if scan.has_key('uuid'):
                            nessusScan.uuid = scan['uuid']
                        if scan.has_key('completion_current'):
                            nessusScan.uuid = scan['completion_current']
                        if scan.has_key('completion_total'):
                            nessusScan.uuid = scan['completion_total']
                        if scan.has_key('start_time'):
                            nessusScan.startTime = scan['start_time']
                        if scan.has_key('owner'):
                            nessusScan.owner = scan['owner']
                        if scan.has_key('scan_name'):
                            nessusScan.scanName = scan['scan_name']
                        self.nessusStructure.scanList.append(nessusScan)

    def scanTimeZoneToStructure(self):
        if self.data['reply']['contents'].has_key('timezones'):
            for timezone in self.data['reply']['contents']['timezones']['timezone']:
                nessusTimeZone = NessusScanTimeZone()
                nessusTimeZone.name = timezone['#text']
                nessusTimeZone.value = timezone['@value']
                self.nessusStructure.scanTimeZonesList.append(nessusTimeZone)

    def scanTemplateToStructure(self):
        if self.data['reply']['contents'].has_key('template'):
            nessusScanTemplate = NessusScanTemplate()
            if self.data['reply']['contents']['template'].has_key('owner'):
                nessusScanTemplate.owner = self.data['reply']['contents']['template']['owner']
            if self.data['reply']['contents']['template'].has_key('readablename'):
                nessusScanTemplate.readablename = self.data['reply']['contents']['template']['readablename']
            if self.data['reply']['contents']['template'].has_key('target'):
                nessusScanTemplate.target = self.data['reply']['contents']['template']['target']
            if self.data['reply']['contents']['template'].has_key('name'):
                nessusScanTemplate.name = self.data['reply']['contents']['template']['name']
            if self.data['reply']['contents']['template'].has_key('policy_id'):
                nessusScanTemplate.policyId = self.data['reply']['contents']['template']['policy_id']
            self.nessusStructure.nessusScanTemplate = nessusScanTemplate

    def reportToStructure(self):
        if self.data['reply']['contents'].has_key('reports'):
            if self.data['reply']['contents']['reports'].has_key('report'):
                for report in self.data['reply']['contents']['reports']['report']:
                    nessusReport = NessusReport()
                    if report.has_key('status'):
                        nessusReport.status = report['status']
                    if report.has_key('readablename'):
                        nessusReport.readablename = report['readablename']
                    if report.has_key('name'):
                        nessusReport.name = report['name']
                    if report.has_key('timestamp'):
                        nessusReport.timestamp = report['timestamp']
                    self.nessusStructure.reportList.append(nessusReport)
        elif self.data['reply']['status'] == 'OK':
            self.nessusStructure.report = True




    def reportHostToStructure(self):
        if self.data['reply']['contents'].has_key('hostlist'):
            if self.data['reply']['contents']['hostlist'].has_key('host'):
                if isinstance(self.data['reply']['contents']['hostlist']['host'], list):
                    for host in self.data['reply']['contents']['hostlist']['host']:
                        reportHost = NessusReportHost()
                        if host.has_key('numchecksconsidered'):
                            reportHost.numchecksconsidered = host['numchecksconsidered']
                        if host.has_key('scanprogresstotal'):
                            reportHost.scanprogresstotal = host['scanprogresstotal']
                        if host.has_key('totalchecksconsidered'):
                            reportHost.totalchecksconsidered = host['totalchecksconsidered']
                        if host.has_key('hostname'):
                            reportHost.hostname = host['hostname']
                        if host.has_key('scanprogresscurrent'):
                            reportHost.scanprogresscurrent = host['scanprogresscurrent']
                        if host.has_key('severity'):
                            reportHost.severity = host['severity']
                        if host.has_key('severitycount'):
                            if host['severitycount'].has_key('item'):
                                for item in host['severitycount']['item']:
                                    nessusHostItem = NessusHostItem()
                                    if item.has_key('severitylevel'):
                                        nessusHostItem.severitylevel = item['severitylevel']
                                    if item.has_key('count'):
                                        nessusHostItem.count = item['count']
                                    reportHost.nessusHostItems.append(nessusHostItem)
                        self.nessusStructure.reportHosts.append(reportHost)
                else:
                    host = self.data['reply']['contents']['hostlist']['host']
                    reportHost = NessusReportHost()
                    if host.has_key('numchecksconsidered'):
                        reportHost.numchecksconsidered = host['numchecksconsidered']
                    if host.has_key('scanprogresstotal'):
                        reportHost.scanprogresstotal = host['scanprogresstotal']
                    if host.has_key('totalchecksconsidered'):
                        reportHost.totalchecksconsidered = host['totalchecksconsidered']
                    if host.has_key('hostname'):
                        reportHost.hostname = host['hostname']
                    if host.has_key('scanprogresscurrent'):
                        reportHost.scanprogresscurrent = host['scanprogresscurrent']
                    if host.has_key('severity'):
                        reportHost.severity = host['severity']
                    if host.has_key('severitycount'):
                        if host['severitycount'].has_key('item'):
                            for item in host['severitycount']['item']:
                                nessusHostItem = NessusHostItem()
                                if item.has_key('severitylevel'):
                                    nessusHostItem.severitylevel = item['severitylevel']
                                if item.has_key('count'):
                                    nessusHostItem.count = item['count']
                                reportHost.nessusHostItems.append(nessusHostItem)
                    self.nessusStructure.reportHosts.append(reportHost)

    def report2HostsPluginToStructure(self):
        if self.data['reply']['contents'].has_key('hostList') and self.data['reply']['contents']['hostList'] is None:
            return
        if self.data['reply']['contents'].has_key('plugin_info'):
            report2HostsPlugin = NessusReport2HostsPlugin()
            plugin = NessusPlugin()
            if self.data['reply']['contents']['plugin_info'].has_key('plugin_id'):
                plugin.pluginId = self.data['reply']['contents']['plugin_info']['plugin_id']
            if self.data['reply']['contents']['plugin_info'].has_key('plugin_name'):
                plugin.pluginName = self.data['reply']['contents']['plugin_info']['plugin_name']
            if self.data['reply']['contents']['plugin_info'].has_key('plugin_family'):
                plugin.pluginFamily = self.data['reply']['contents']['plugin_info']['plugin_family']
            report2HostsPlugin.plugin = plugin
            if self.data['reply']['contents'].has_key('hostList'):
                for host in self.data['reply']['contents']['hostList']['host']:
                    nessusReportHost = NessusReportHost()
                    if host.has_key('hostname'):
                        nessusReportHost.hostname = host['hostname']
                    if host.has_key('port'):
                        nessusReportHost.port = host['port']
                    if host.has_key('protocol'):
                        nessusReportHost.protocol = host['protocol']
                    report2HostsPlugin.hostList.append(nessusReportHost)
            self.nessusStructure.report2HostPlugin = report2HostsPlugin




    def reportPortToStructure(self):
        if self.data['reply']['contents'].has_key('portlist'):
            if self.data['reply']['contents']['portlist'].has_key('port'):
                if isinstance(self.data['reply']['contents']['portlist']['port'], list):
                    for port in self.data['reply']['contents']['portlist']['port']:
                        reportPort = NessusReportPort()
                        if port.has_key('portnum'):
                            reportPort.portNumber = port['portnum']
                        if port.has_key('protocol'):
                            reportPort.protocol = port['protocol']
                        if port.has_key('severity'):
                            reportPort.severity = port['severity']
                        if port.has_key('svcName'):
                            reportPort.svcName = port['svcName']
                        if port.has_key('severitycount'):
                            if port['severitycount'].has_key('item'):
                                for item in port['severitycount']['item']:
                                    nessusHostItem = NessusHostItem()
                                    if item.has_key('severitylevel'):
                                        nessusHostItem.severitylevel = item['severitylevel']
                                    if item.has_key('count'):
                                        nessusHostItem.count = item['count']
                                    reportPort.nessusHostItems.append(nessusHostItem)
                        self.nessusStructure.reportPortList.append(reportPort)
                else:
                    port = self.data['reply']['contents']['portlist']['port']
                    reportPort = NessusReportPort()
                    if port.has_key('portnum'):
                        reportPort.portNumber = port['portnum']
                    if port.has_key('protocol'):
                        reportPort.protocol = port['protocol']
                    if port.has_key('severity'):
                        reportPort.severity = port['severity']
                    if port.has_key('svcName'):
                        reportPort.svcName = port['svcName']
                    if port.has_key('severitycount'):
                        if port['severitycount'].has_key('item'):
                            for item in port['severitycount']['item']:
                                nessusHostItem = NessusHostItem()
                                if item.has_key('severitylevel'):
                                    nessusHostItem.severitylevel = item['severitylevel']
                                if item.has_key('count'):
                                    nessusHostItem.count = item['count']
                                reportPort.nessusHostItems.append(nessusHostItem)
                    self.nessusStructure.reportPortList.append(reportPort)

    def reportPortDetailToStructure(self):
        if self.data['reply']['contents'].has_key('portDetails'):
            if self.data['reply']['contents']['portDetails'].has_key('ReportItem') and self.data['reply']['contents']['portDetails']['ReportItem'] is not None:
                reportPortDetail = NessusReportPortDetail()
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('item_id'):
                    reportPortDetail.itemId = self.data['reply']['contents']['portDetails']['ReportItem']['item_id']
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('port'):
                    reportPortDetail.port = self.data['reply']['contents']['portDetails']['ReportItem']['port']
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('severity'):
                    reportPortDetail.severity = self.data['reply']['contents']['portDetails']['ReportItem']['severity']
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('pluginID'):
                    reportPortDetail.pluginId = self.data['reply']['contents']['portDetails']['ReportItem']['pluginID']
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('pluginName'):
                    reportPortDetail.pluginName = self.data['reply']['contents']['portDetails']['ReportItem']['pluginName']
                if self.data['reply']['contents']['portDetails']['ReportItem'].has_key('data') and self.data['reply']['contents']['portDetails']['ReportItem']['data'] is not None:
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('bid'):
                        reportPortDetail.bid = self.data['reply']['contents']['portDetails']['ReportItem']['data']['bid']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cert'):
                        reportPortDetail.cert = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cert']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cpe'):
                        reportPortDetail.cpe = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cpe']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cve'):
                        reportPortDetail.cve = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cve']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cvss_base_score'):
                        reportPortDetail.cvss_base_score = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cvss_base_score']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cvss_temporal_score'):
                        reportPortDetail.cvss_temporal_score = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cvss_temporal_score']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cvss_temporal_vector'):
                        reportPortDetail.cvss_temporal_vector = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cvss_temporal_vector']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('cvss_vector'):
                        reportPortDetail.cvss_vector = self.data['reply']['contents']['portDetails']['ReportItem']['data']['cvss_vector']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('description'):
                        reportPortDetail.description = self.data['reply']['contents']['portDetails']['ReportItem']['data']['description']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('edb-id'):
                        reportPortDetail.edbId = self.data['reply']['contents']['portDetails']['ReportItem']['data']['edb-id']
                    if self.data['reply']['contents']['portDetails']['ReportItem']['data'].has_key('fname'):
                        reportPortDetail.fname = self.data['reply']['contents']['portDetails']['ReportItem']['data']['fname']
                self.nessusStructure.reportPortDetail = reportPortDetail

    def tagToNessusStructure(self):
        if self.data['reply']['contents'].has_key('tags'):
            if self.data['reply']['contents']['tags'].has_key('tag'):
                if isinstance(self.data['reply']['contents']['tags']['tag'],list):
                    for tag in self.data['reply']['contents']['tags']['tag']:
                        nessusTag = NessusTag()
                        nessusTag.name = tag['name']
                        nessusTag.value = tag['value']
                        self.nessusStructure.nessusTags.append(nessusTag)
                else:
                    nessusTag = NessusTag()
                    nessusTag.name = self.data['reply']['contents']['tags']['tag']['name']
                    nessusTag.value = self.data['reply']['contents']['tags']['tag']['value']
                    self.nessusStructure.nessusTags.append(nessusTag)

    def auditTrailToStructure(self):
        if self.data['reply']['contents'].has_key('hasaudittrail'):
            self.nessusStructure.hasAuditTrail = self.data['reply']['contents']['hasaudittrail']

    def reportAttributesToStructure(self):
        if self.data['reply']['contents'].has_key('reportattributes'):
            if self.data['reply']['contents']['reportattributes'].has_key('attribute'):
                for attribute in self.data['reply']['contents']['reportattributes']['attribute']:
                    nessusAttribute = NessusReportAttribute()
                    if attribute.has_key('name'):
                        nessusAttribute.name = attribute['name']
                    if attribute.has_key('readable_name'):
                        nessusAttribute.readableName = attribute['readable_name']
                    if attribute.has_key('control'):
                        attributeControl = NessusReportAttributeControl()
                        if attribute['control'].has_key('type'):
                            attributeControl.type = attribute['control']['type']
                        if attribute['control'].has_key('readable_regex'):
                            attributeControl.readableRegex = attribute['control']['readable_regex']
                        if attribute['control'].has_key('regex'):
                            attributeControl.regex = attribute['control']['regex']
                        nessusAttribute.nessusControl = attributeControl
                    if attribute.has_key('operators'):
                        for operator in attribute['operators']['operator']:
                            nessusAttribute.operators.append(operator)
                    self.nessusStructure.nessusReportAttributes.append(nessusAttribute)

    def hasKBToStructure(self):
        if self.data['reply']['contents'].has_key('haskb'):
            self.nessusStructure.hasKB = self.data['reply']['contents']['hasKB']

    def canDeleteToStructure(self):
        if self.data['reply']['contents'].has_key('candelete'):
            self.nessusStructure.canDelete = self.data['reply']['contents']['canDelete']

    def deleteItemToStructure(self):
        if self.data['reply']['contents'].has_key('itemdeleted'):
            self.nessusStructure.itemDeleted = self.data['reply']['contents']['itemDeleted']


    def vulnerabilityToStructure(self):
        if self.data['reply']['contents'].has_key('vulnlist'):
            for vuln in self.data['reply']['contents']['vulnlist']['vulnerability']:
                nessusVuln = NessusVulnerability()
                if vuln.has_key('count'):
                    nessusVuln.count = vuln['count']
                if vuln.has_key('plugin_id'):
                    nessusVuln.count = vuln['plugin_id']
                if vuln.has_key('plugin_name'):
                    nessusVuln.count = vuln['plugin_name']
                if vuln.has_key('plugin_family'):
                    nessusVuln.count = vuln['plugin_family']
                if vuln.has_key('severity'):
                    nessusVuln.count = vuln['severity']
                self.nessusStructure.nessusVulns.append(nessusVuln)


class NessusHostItem():
    def __init__(self):
        self.severitylevel = None
        self.count = None

class NessusStructure():
    '''
    Definition for the data returned from the Nessusd server.
    '''
    def __init__(self):
        self.feed = None
        self.secureSettings = None  #For secureSettings and secureSettingsList
        self.serverPreferences = None #For serverPreferences and serverPreferencesList
        self.serverUpdate = None
        self.serverRegistration = None
        self.serverLoad = None
        self.uuid = None
        self.serverCert = None
        self.pluginsProcess = None  #Instructs Nessus server to request a plugin update from Teneable Network Security
        self.nessusUser = None
        self.nessusUsers = []
        self.pluginsList = []
        self.pluginsAttributes = []
        self.pluginsListFamily = []
        self.pluginsDescription = None
        self.pluginsPreferences = None
        self.pluginsAttributeFamilySearch = None
        self.pluginsAttributePluginSearch = None
        self.md5Structure = []
        self.pluginsDescriptions = []
        self.policyPreferences = []
        self.nessusPolicies = []
        self.policyDeleted = None
        self.policyDownloaded = None
        self.fileUploaded = None
        self.scan = None
        self.scanList = []
        self.scanTimeZonesList = []
        self.nessusScanTemplate = None
        self.report = None
        self.reportHosts = []
        self.reportList = []
        self.report2Host = None
        self.report2HostPlugin = None
        self.reportPortList = []
        self.reportPortDetail = None
        self.nessusTags = []
        self.hasAuditTrail = None
        self.nessusReportAttributes = []
        self.hasKB = None
        self.canDelete = None
        self.itemDeleted = None
        self.nessusVulns = []


class NessusFeed():
    def __init__(self):
        self.feed = None
        self.reportEmail = None
        self.tags = None
        self.msp = None
        self.multiScanner = None
        self.pluginRules = None
        self.expiration = None
        self.uiVersion = None
        self.nessusType = None
        self.diff = None
        self.expirationTime = None
        self.loadedPluginSet = None
        self.serverVersion = None
        self.webServerVersion = None

class NessusSecureSettings():
    def __init__(self):
        self.proxyPassword = None
        self.proxyPort = None
        self.customHost = None
        self.proxyUserName = None
        self.userAgent = None
        self.proxy = None
        self.preferences = None

class NessusServerLoad():
    def __init__(self):
        self.numScans = None
        self.numSessions = None
        self.numHosts = None
        self.numTcpSessions = None
        self.loadAvg = None
        self.platform = None

class NessusUser():
    def __init__(self):
        self.name = None
        self.admin = None
        self.idx = None
        self.lastLogin = None

class NessusFamily():
    def __init__(self):
        self.familyName = None
        self.familyMembers = None
        self.familyStatus = None

class NessusPluginsDescription():
    def __init__(self):
        self.bid = None
        self.cpe = None
        self.cve = None
        self.cvssBaseScore = None
        self.cvssTemporalScore = None
        self.cvssTemporalVector = None
        self.cvssVector  = None
        self.description = None
        self.exploitAvailable = None
        self.exploitabilityEase = None
        self.patchPublicationDate = None
        self.pluginModificationDate = None
        self.pluginPatchDate = None
        self.pluginType = None
        self.pluginVersion = None
        self.riskFactor = None
        self.seeAlso = None
        self.solution = None
        self.stigSeverity = None
        self.synopsis = None
        self.vulnPublicationDate = None
        self.xref = []
        self.pluginFamily = None
        self.pluginId = None
        self.pluginName = None
        self.policyServerPreferences = []

class NessusPluginPreference():
    def __init__(self):
        self.fullName = None
        self.pluginName = None
        self.preferenceName = None
        self.preferenceType = None
        self.preferenceValues = None
        self.pluginId = None

class NessusPlugin():
    def __init__(self):
        self.pluginFamily = None
        self.pluginFileName = None
        self.pluginId = None
        self.pluginName = None
        self.pluginStatus = None

class NessusPluginAttributeControl():
    def __init__(self):
        self.readableRegex = None
        self.regex = None
        self.type = None
        self.list = []

class NessusPluginAttribute():
    def __init__(self):
        self.name = None
        self.readableName = None
        self.controls = None
        self.operators = [] #List of str objects.


class NessusMd5Entry():
    def __init__(self):
        self.fileName = None
        self.md5 = None

class NessusPolicy():
    def __init__(self):
        self.policyFamilySelection = []
        self.individualPluginSelection = []
        self.policyComments = None
        self.serverPolicyPreferences = []
        self.pluginPreferences = []
        self.policyId = None
        self.policyName = None
        self.policyOwner = None
        self.policyVisibility = None

class NessusPolicyPreference():
    def __init__(self):
        self.name = None
        self.value = None

class NessusScan():
    def __init__(self):
        self.owner = None
        self.scanName = None
        self.startTime = None
        self.uuid = None
        self.readableName = None
        self.status = None
        self.completionCurrent = None
        self.completionTotal = None
        self.scanPolicies = []

class NessusScanTimeZone():
    def __init__(self):
        self.name = None
        self.value = None

class NessusScanTemplate():
    def __init__(self):
        self.owner = None
        self.readablename = None
        self.target = None
        self.name = None
        self.policyId = None

class NessusReport():
    def __init__(self):
        self.name = None
        self.readablename = None
        self.status = None
        self.timeStamp = None

class NessusReportHost():
    def __init__(self):
        self.numchecksconsidered = None
        self.scanprogresstotal = None
        self.totalchecksconsidered = None
        self.hostname = None
        self.scanprogresscurrent= None
        self.port = None
        self.protocol = None
        self.nessusHostItems = []

class NessusHostItem():
    def __init__(self):
        self.severitylevel = None
        self.count = None

class NessusReport2HostsPlugin():
    def __init__(self):
        self.plugin = None
        self.hostList = []

class NessusReportPort():
    def __init__(self):
        self.portNumber = None
        self.protocol = None
        self.severity = None
        self.svcName = None
        self.nessusHostItems = []

class NessusReportPortDetail():
    def __init__(self):
        self.itemId = None
        self.port = None
        self.severity = None
        self.pluginId = None
        self.pluginName = None
        self.data = None
        self.bid = None
        self.cert = None
        self.cpe = None
        self.cve = None
        self.cvss_base_score = None
        self.cvss_temporal_score = None
        self.cvss_temporal_vector = None
        self.cvss_vector = None
        self.description = None
        self.edbId = None
        self.fname = None

class NessusTag():
    def __init__(self):
        self.name = None
        self.value = None

class NessusReportAttribute():
    def __init__(self):
        self.name = None
        self.readableName = None
        self.nessusControl = None
        self.operators = []

class NessusReportAttributeControl():
    def __init__(self):
        self.type = None
        self.regex = None
        self.readableRegex = None

class NessusVulnerability():
    def __init__(self):
        self.pluginId = None
        self.pluginName = None
        self.pluginFamily = None
        self.count = None
        self.severity = None