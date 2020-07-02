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
In a sense it is similar to tzworks' evtwalker and elmo combination.It is much faster than python-evtx as it can use either:

* Windows native code (OpenBackupEventLog) using --mode native; or 
* XML using pyevtx-rs --mode xml.

*Requires pywin32, windows only.*

```
>py kpulp.py --help
usage: kpulp.py [-h] [--output OUTPUT] [--output-format {json}] [--additional-dlls EXTRADLLPATH] [--debug]
                [--mode {xml,native}]
                LOGFILE.evtx [LOGFILE.evtx ...]

Parse EVTX files

positional arguments:
  LOGFILE.evtx          List of logfiles to parse. Will expand wildcards.

optional arguments:
  -h, --help            show this help message and exit
  --output OUTPUT, -o OUTPUT
                        Destination, if - then STDOUT (default)
  --output-format {json}, -f {json}
                        Output format, choices are:json
  --additional-dlls EXTRADLLPATH
                        Directory with additoinal DLLs to load (as created by dllraider)
  --debug, -d           Debug level messages
  --mode {xml,native}   Parsing mode: xml or native
```

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
                match => [ "TimeGenerated" , "ISO8601", "EEE, MMMM d, YYYY H:m:s" ]
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
