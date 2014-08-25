pynessus-rest
=============

Python Library to use the implementation of the REST protocol of Tenable’s Nessus scanner. You can use Nessus from your scripts easily!

## Installation
Recommended installation using setuptools. Just type:
python setup.py install

##Usage.
Some examples to use pynessus-rest.

* Login with the Nessus server.
```
from pynessus.rest.client.NessusClient import NessusClient
client = NessusClient('127.0.0.1','8834')
client.login('adastra','adastra')
```

* Print the Nessus Feed.
```
print client.feed()
```

* List of policies
```
client.policyList()
```

* Upload a policy
```
client.policyFileUpload("tested.nessus", contents)
```

* Import a policy
```
client.policyFilePolicyImport("tested.nessus")
```

* Start a new scan
```
client.scanNew("8.8.8.4",'1','testScan')
```

* Stop a existing scan
```
client.scanStop('ec665c9e-ce24-336b-acb4-e2b199fac1800854abce5c111a8d')
```

* Creates a new Scan Template
```
client.scanTemplateNew('1','127.0.0.1', 'NewTemplate')
```

* Launches a new Scan using the specified templte
```
client.scanTemplateLaunch('NewTemplate')
```

* List of generated reports
```
client.reportList()
```

* Report Details for a specific port number
```
client.reportDetails('e26d6acf-75b2-a4cb-0ca6-879f0da6ab571a375b02539ff736', '192.168.1.222', '139', 'tcp')
```

* List of host for a specific report
```
client.reportHosts("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb")
```

* List of host for a specific report
```
client.reportHosts("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb")
```

## Using NessusConverter to parse the JSON Response.
The JSON response for some functions of Nessus is very large and complex. Usually, parsing that data structures is a hard job. The NessusConverter class parses the JSON response and generates a Python object with every field filled with the data received from the server.
Check the NessusConverter function and NessusStructure attributes to get a clear idea.

* List the report Attributes.
```
nessusConverter = NessusConverter(client.reportAttributesList("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb"))
nessusConverter.reportAttributesToStructure()
for reportAttribute in nessusConverter.nessusStructure.nessusReportAttributes:
	print reportAttribute.type +' - '+ reportAttribute.regex
```

* Report Tags
```
nessusConverter = NessusConverter(client.reportTags("2e8ed9f5-79b5-4f60-d223-bc08e9688c79a606b97c670a7deb", '127.0.0.1', jsonFormat=True))
nessusConverter.tagToNessusStructure()
for tag in nessusConverter.nessusStructure.nessusTags:
	print tag.name +' - '+ tag.value
```

* Nessus Structure with the Scans in execution.
```
nessusConverter = NessusConverter(client.scanList())
structure = nessusConverter.scanListToStructure()
```

##Contact.
If you have any issue or query, just send an email to:
debiadastra at gmail dot com
