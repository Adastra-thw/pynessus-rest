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

class NessusConverter():
    '''
    Class to convert the data structures from Nessus to pynessus-rest data-model objects.
    '''
    def __init__(self, data):
        self.data = data
        self.nessusStructure = NessusStructure()

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
        nessusFeed.feed = self.data['reply']['contents']['feed']
        nessusFeed.reportEmail = self.data['reply']['contents']['reportEmail']
        nessusFeed.tags = self.data['reply']['contents']['tags']
        nessusFeed.msp = self.data['reply']['contents']['msp']
        nessusFeed.multiScanner = self.data['reply']['contents']['multi_scanner']
        nessusFeed.pluginRules = self.data['reply']['contents']['plugin_rules']
        nessusFeed.expiration = self.data['reply']['contents']['expiration']
        nessusFeed.uiVersion = self.data['reply']['contents']['nessus_ui_version']
        nessusFeed.nessusType = self.data['reply']['contents']['nessus_type']
        nessusFeed.diff = self.data['reply']['contents']['diff']
        nessusFeed.expirationTime = self.data['reply']['contents']['expiration_time']
        nessusFeed.loadedPluginSet = self.data['reply']['contents']['loaded_plugin_set']
        nessusFeed.serverVersion = self.data['reply']['contents']['server_version']
        nessusFeed.webServerVersion = self.data['reply']['contents']['web_server_version']
        self.nessusStructure.feed = nessusFeed

    def secureSettingsListToStructure(self):
        nessusSecureSettings = NessusSecureSettings()
        if self.data['reply']['contents'].has_key('securesettings'):
            if self.data['reply']['contents']['securesettings'].has_key('proxysettings'):
                nessusSecureSettings.proxyPassword = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_password']
                nessusSecureSettings.proxyPort = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_port']
                nessusSecureSettings.customHost = self.data['reply']['contents']['securesettings']['proxysettings']['custom_host']
                nessusSecureSettings.proxyUserName = self.data['reply']['contents']['securesettings']['proxysettings']['proxy_username']
                nessusSecureSettings.userAgent = self.data['reply']['contents']['securesettings']['proxysettings']['user_agent']
                nessusSecureSettings.proxy = self.data['reply']['contents']['securesettings']['proxysettings']['proxy']
                self.nessusStructure.secureSettings = nessusSecureSettings

    def serverPreferencesListToStructure(self):
        if self.data['reply']['contents'].has_key('serverpreferences'):
            self.nessusStructure.serverPreferences = self.data['reply']['contents']['serverpreferences']

    def serverUpdateToStructure(self):
       if self.data['reply']['contents'].has_key('update'):
           self.nessusStructure.serverUpdate = self.data['reply']['contents']['serverupdate']

    def serverRegisterToStructure(self):
        if self.data['reply']['contents'].has_key('registration'):
            self.nessusStructure.serverRegistration = self.data['reply']['contents']['registration']

    def serverLoadToStructure(self):
        if self.data['reply']['contents'].has_key('load'):
            nessusServerLoad = NessusServerLoad()
            nessusServerLoad.numScans = self.data['reply']['contents']['load']['num_scans']
            nessusServerLoad.numSessions = self.data['reply']['contents']['load']['num_sessions']
            nessusServerLoad.numHosts = self.data['reply']['contents']['load']['num_hosts']
            nessusServerLoad.numTcpSessions = self.data['reply']['contents']['load']['num_tcp_sessions']
            nessusServerLoad.loadAvg = self.data['reply']['contents']['load']['loadavg']
        if self.data['reply']['contents'].has_key('platform'):
            nessusServerLoad.platform = self.data['reply']['contents']['platform']

    def serverUuidToStructure(self):
        if self.data['reply']['contents'].has_key('uuid'):
            self.nessusStructure.uuid = self.data['reply']['contents']['uuid']

    def serverGetCertToStructure(self):
        if self.data is not None:
            self.nessusStructure.serverCert = self.data

    def serverPluginsProcessToStructure(self):
         if self.data['reply']['contents'].has_key('plugins_processing'):
            self.nessusStructure.pluginsProcess = self.data['reply']['contents']['plugins_processing']

    def userListToStructure(self):
         if self.data['reply']['contents'].has_key('users'):
             for user in self.data['reply']['contents']['user']:
                 nessusUser = NessusUser()
                 nessusUser.name = user['name']
                 nessusUser.admin = user['admin']
                 nessusUser.idx = user['idx']
                 nessusUser.lastLogin = user['lastlogin']
                 self.nessusStructure.nessusUsers.append(nessusUser)


    def userToStructure(self):
         if self.data['reply']['contents'].has_key('user'):
            nessusUser = NessusUser()
            nessusUser.name = self.data['reply']['contents']['user']['name']
            nessusUser.admin = self.data['reply']['contents']['user']['admin']
            nessusUser.idx = self.data['reply']['contents']['user']['idx']
            nessusUser.lastLogin = self.data['reply']['contents']['user']['lastlogin']
            self.nessusStructure.nessusUser = nessusUser

    def pluginsListToStructure(self):
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('family'):
                 for family in self.data['reply']['contents']['pluginfamilylist']['family']:
                     nessusPlugin = NessusFamily()
                     nessusPlugin.familyMembers = family['numfamilymembers']
                     nessusPlugin.familyName = family['familyname']
                     self.nessusStructure.pluginsList.append(nessusPlugin)

    def pluginsAttributesToStructure(self):
        if self.data['reply']['contents'].has_key('pluginsattributes'):
            if self.data['reply']['contents']['pluginsattributes'].has_key('attribute'):
                for attribute in self.data['reply']['contents']['pluginsattributes']['attribute']:
                    pluginAttribute = NessusPluginAttribute()
                    if self.data['reply']['contents']['pluginsattributes']['attribute'].has_key('name'):
                        pluginAttribute.name = self.data['reply']['contents']['pluginsattributes']['attribute']['name']
                    if self.data['reply']['contents']['pluginsattributes']['attribute'].has_key('readable_name'):
                        pluginAttribute.name = self.data['reply']['contents']['pluginsattributes']['attribute']['readable_name']


                    if self.data['reply']['contents']['pluginsattributes']['attribute'].has_key('control'):
                        control = NessusPluginAttributeControl()
                        if self.data['reply']['contents']['pluginsattributes']['attribute']['control'].has_key('readable_regex'):
                            control.readableRegex = self.data['reply']['contents']['pluginsattributes']['attribute']['control']['readable_regex']
                        if self.data['reply']['contents']['pluginsattributes']['attribute']['control'].has_key('regex'):
                            control.regex = self.data['reply']['contents']['pluginsattributes']['attribute']['control']['regex']
                        if self.data['reply']['contents']['pluginsattributes']['attribute']['control'].has_key('type'):
                            control.type = self.data['reply']['contents']['pluginsattributes']['attribute']['control']['type']
                        if self.data['reply']['contents']['pluginsattributes']['attribute']['control'].has_key('list'):
                            control.list = self.data['reply']['contents']['pluginsattributes']['attribute']['control']['list']['entry']
                        pluginAttribute.controls.append(control)
                    if self.data['reply']['contents']['pluginsattributes']['attribute'].has_key('operators'):
                        pluginAttribute.operators = self.data['reply']['contents']['pluginsattributes']['attribute']['operators']['operator']
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
            if self.data['reply']['contents']['plugindescription'].has_key('pluginattributes'):
                pluginsDescription = NessusPluginsDescription()
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
                    pluginsDescription.description = self.data['reply']['contents']['plugindescription']['pluginattributes']['descriptor']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('exploit_available'):
                    pluginsDescription.exploitAvailable = self.data['reply']['contents']['plugindescription']['pluginattributes']['exploit_available']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('exploitability_ease'):
                    pluginsDescription.exploitabilityEase = self.data['reply']['contents']['plugindescription']['pluginattributes']['exploitability_ease']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('patch_publication_date'):
                    pluginsDescription.pluginPublicationDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['patch_publication_date']
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
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('vuln_publication_date'):
                    pluginsDescription.vulnPublicationDate = self.data['reply']['contents']['plugindescription']['pluginattributes']['vuln_publication_date']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('xref'):
                    pluginsDescription.xref = self.data['reply']['contents']['plugindescription']['pluginattributes']['xref']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('pluginfamily'):
                    pluginsDescription.pluginFamily = self.data['reply']['contents']['plugindescription']['pluginattributes']['pluginfamily']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('pluginid'):
                    pluginsDescription.pluginId = self.data['reply']['contents']['plugindescription']['pluginattributes']['pluginid']
                if self.data['reply']['contents']['plugindescription']['pluginattributes'].has_key('pluginname'):
                    pluginsDescription.pluginName = self.data['reply']['contents']['plugindescription']['pluginattributes']['pluginname']
                self.nessusStructure.pluginsDescription = pluginsDescription

    def pluginsPreferencesToStructure(self):
        if self.data['reply']['contents'].has_key('pluginspreferences'):
            if self.data['reply']['contents']['pluginspreferences'].has_key('item'):
                for item in self.data['reply']['contents']['pluginspreferences']['item']:
                    pluginPreference = NessusPluginPreference()
                    pluginPreference.fullName = self.data['reply']['contents']['pluginspreferences']['item']['fullname']
                    pluginPreference.pluginName = self.data['reply']['contents']['pluginspreferences']['item']['pluginname']
                    pluginPreference.preferenceName = self.data['reply']['contents']['pluginspreferences']['item']['preferencename']
                    pluginPreference.preferenceType = self.data['reply']['contents']['pluginspreferences']['item']['preferencetype']
                    pluginPreference.preferenceValues = self.data['reply']['contents']['pluginspreferences']['item']['preferencevalues']
                    self.nessusStructure.pluginsPreferences = pluginPreference

    def pluginsAttributeFamilySearchToStructure(self): #Test: client.pluginsAttributesFamilySearch('match','and','modicon','description')
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('family'):
                 self.nessusStructure.pluginsAttributeFamilySearch = self.data['reply']['contents']['pluginfamilylist']['family']


    def pluginsAttributePluginSearchToStructure(self): #Test: client.pluginsAttributesFamilySearch('match','and','modicon','description')
         if self.data['reply']['contents'].has_key('pluginfamilylist'):
             if self.data['reply']['contents']['pluginfamilylist'].has_key('plugin'):
                 pluginFamily = NessusPlugin()
                 pluginFamily.pluginFamily = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginfamily']
                 pluginFamily.pluginFileName = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginfilename']
                 pluginFamily.pluginId = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginid']
                 pluginFamily.pluginName = self.data['reply']['contents']['pluginfamilylist']['plugin']['pluginname']
                 self.nessusStructure.pluginsAttributePluginSearch = pluginFamily


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
        self.pluginPublicationDate = None
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

class NessusPluginPreference():
    def __init__(self):
        self.fullName = None
        self.pluginName = None
        self.preferenceName = None
        self.preferenceType = None
        self.preferenceValues = None

class NessusPlugin():
    def __init__(self):
        self.pluginFamily = None
        self.pluginFileName = None
        self.pluginId = None
        self.pluginName = None

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
        self.controls = []
        self.operators = [] #List of str objects.



