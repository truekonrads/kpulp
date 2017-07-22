```


██╗  ██╗██████╗ ██╗   ██╗██╗     ██████╗ 
██║ ██╔╝██╔══██╗██║   ██║██║     ██╔══██╗
█████╔╝ ██████╔╝██║   ██║██║     ██████╔╝
██╔═██╗ ██╔═══╝ ██║   ██║██║     ██╔═══╝ 
██║  ██╗██║     ╚██████╔╝███████╗██║     
╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚═╝     
                                         

```
# Konrads' Pen-Ultimate (Windows) Log File Parser

This small utility parses saved Windows EVTX files using Windows native routines and outputs JSON-ND.
In a sense it is similar to tzworks' evtwalker and elmo combination. It is much faster than python-evtx as it uses Windows native code.
*Requires pywin32, windows only.*

The main redeeming feature is parsing of log text narrative into fields, e.g. 
```
The Windows Filtering Platform has permitted a connection.

Application Information:
	Process ID:		2440
	Application Name:	\device\harddiskvolume3\windows\system32\svchost.exe

Network Information:
	Direction:		Inbound
	Source Address:		ff02::c
...

```
Would be parsed as:

|Key    | Value |
| --- | --- |
|Short Description | The Windows Filtering Platform has permitted a connection. |
|Application Information Process ID | 2440 |
|Application Information Application Name | \device\harddiskvolume3\windows\system32\svchost.exe| 
|Network Information Direction | Inbound |
|Network Information Source Address | ff02::c |

This is incredibly handy when dealing with events where there are same name subkey's such as (Source) Account Name and (Target) Account Name.

## Importing to ElasticSearch using logstash ##
Use this sample config snipper to import into your ElasticSearch using Logstash:
```
input {
stdin{
        codec => "json"

  }
}
filter {
        date {
                match => [ "TimeGenerated" , "EEE, MMMM d, YYYY H:m:s" ]
        }
}
output {
  elasticsearch { hosts => ["localhost:9200"]
#                ssl => true

#       user => elastic
#    password => changeme

 }
#  stdout{
#               codec => rubydebug
#       }
  }

```
And then do:

```pv ./out3.json |/usr/share/logstash/bin/logstash -f ./stashme.conf```

(the pv isn't required, but boy isn't it awesome?)
