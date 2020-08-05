import logging
import re
import argparse
import glob
import json
import time
import sys
import win32evtlog
import win32api
import win32con
import pywintypes
import os
import bunch
import evtx
from datetime import datetime
from lxml import etree
import tzlocal
import pytz
from bs4 import BeautifulSoup
OUTPUT_FORMATS = "json".split(" ")
LANGID = win32api.MAKELANGID(win32con.LANG_NEUTRAL, win32con.SUBLANG_NEUTRAL)
DLLCACHE = {}
DLLMSGCACHE = {}
LOGGER = logging.getLogger("kpulp")
LOGGER.setLevel(logging.INFO)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def loadDLLsInCache(directory=None):

    if directory:

        for source in os.listdir(directory):
            dirpath = os.path.join(directory, source)
            if os.path.isdir(dirpath):
                for e in os.listdir(dirpath):

                    if e.lower().endswith(".dll"):
                        # dllHandle = loadDLL(dllName)
                        dllPath = os.path.join(dirpath, e)
                        LOGGER.debug(
                            "Loading {} for {}".format(dllPath, source))
                        if source not in DLLCACHE:
                            DLLCACHE[source] = {}
                        try:
                            dllHandle = loadDLL(dllPath)
                            DLLCACHE[source][e] = dllHandle
                        except pywintypes.error as exc:
                            LOGGER.warn(
                                "Error loading {}: {}".format(dllPath, exc))
        return

    keyName = u'SYSTEM\\CurrentControlSet\\Services\\EventLog'
    h1 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, keyName)

    for (typeName, _, __, ___) in win32api.RegEnumKeyEx(h1):
        keyName = u'SYSTEM\\CurrentControlSet\\Services\\EventLog\\{}'.format(
            typeName)
        h2 = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, keyName)
        for (sourceName, _, __, ___) in win32api.RegEnumKeyEx(h2):
            keyName = u'SYSTEM\\CurrentControlSet\\Services\\EventLog\\{}\\{}'.format(
                typeName, sourceName)
            h3 = win32api.RegOpenKeyEx(
                win32con.HKEY_LOCAL_MACHINE, keyName, 0, win32con.KEY_READ)
            LOGGER.debug("Enumerating {}".format(keyName))
            try:

                dllNames = win32api.RegQueryValueEx(
                    h3, "EventMessageFile")[0].split(";")
                if sourceName not in DLLCACHE:
                    DLLCACHE[sourceName] = {}
                for dllName in dllNames:
                    if dllName:
                        dllHandle = loadDLL(dllName)
                        DLLCACHE[sourceName][dllName] = dllHandle
            except pywintypes.error as e:
                if e.args[0] == 2:  # value not found
                    pass
                else:
                    raise e


def loadDLL(dllName):

    dllPath = win32api.ExpandEnvironmentStrings(dllName)
    LOGGER.debug("Loading library {}".format(dllPath))
    dllHandle = win32api.LoadLibraryEx(
        dllPath, 0, win32con.LOAD_LIBRARY_AS_DATAFILE)
    return dllHandle


def expandString(event):

    cachekey = event.SourceName + "/" + str(event.EventID)
    try:
        if cachekey in DLLMSGCACHE:
            dllName = DLLMSGCACHE[cachekey]
            if dllName is None:
                return ""

            dllHandle = DLLCACHE[event.SourceName][dllName]
            data = win32api.FormatMessageW(win32con.FORMAT_MESSAGE_FROM_HMODULE,
                                           dllHandle, event.EventID, LANGID, event.StringInserts)
            return data
        elif event.SourceName not in DLLCACHE:
            LOGGER.debug("Event {}/{} not in cache".format(
                event.SourceName, event.EventID))
            DLLMSGCACHE[cachekey] = None

        else:

            for (dllName, dllHandle) in DLLCACHE[event.SourceName].items():
                try:
                    data = win32api.FormatMessageW(win32con.FORMAT_MESSAGE_FROM_HMODULE,
                                                   dllHandle, event.EventID, LANGID, event.StringInserts)

                    DLLMSGCACHE[cachekey] = dllName
                    return data
                except win32api.error:
                    pass  # not in this DLL
                except SystemError:
                    pass
    except pywintypes.error:
        pass
    LOGGER.debug("Unable to expand data for {} EventID: {}".format(
        event.SourceName, event.EventID))
    DLLMSGCACHE[cachekey] = None  # no DLLs known to expand this message
    # from IPython import embed
    # embed()
    return ""


def readevents(path):
    logHandle = None
    try:
        logHandle = win32evtlog.OpenBackupEventLog(
            None, path)  # None=NULL means local host

        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = win32evtlog.GetNumberOfEventLogRecords(logHandle)
        LOGGER.info("Total number of records for {} is: {}".format(path, total))

        # if "security" in path.lower():
        #     logType = "Security"
        # elif "application" in path.lower():
        #     logType = "Application"
        # elif "system" in path.lower():
        #     logType = "System"
        # else:
        #     LOGGER.error("Unknown log type - put something in path")
        #     sys.exit(-1)
        event_dict = None
        local_tz = tzlocal.get_localzone()
        while True:
            events = win32evtlog.ReadEventLog(logHandle, flags, 0)
            if events:
                for event in events:
                    event_dict = {}
                    # print(event.TimeGenerated)
                    # from IPython import embed
                    # embed()
                    # event_dict['TimeGenerated'] = event.TimeGenerated.strftime("%#c")
                    dt = local_tz.localize(
                        event.TimeGenerated).astimezone(pytz.utc)
                    event_dict['TimeGenerated'] = dt.isoformat()
                    event_dict['SourceName'] = event.SourceName
                    # See https://social.msdn.microsoft.com/Forums/sqlserver/en-US/67e49b0b-a9b8-4263-9233-079776f4cbbc/systemdiagnosticseventlogentry-is-showing-wrong-eventid-in-the-eventlogentrymessage-string-?forum=vbgeneral
                    # EventID might be Instance ID and so we 0xFFFF it to bring back to EventID
                    event_dict['Id'] = event.EventID & 0xFFFF
                    event_dict['EventType'] = event.EventType
                    event_dict['ComputerName'] = event.ComputerName

                    if event.StringInserts:
                        event_dict['data'] = "|".join(event.StringInserts)

                    description = expandString(event)
                    event_dict['Description'] = description
                    if description:
                        event_dict.update(description_to_fields(description))
                        first_line = description.split("\r\n")[0]
                        event_dict['Short Description'] = first_line
                    yield event_dict
            else:
                break
    except pywintypes.error as e:
        LOGGER.error(str(e))
        if e.winerror == 1722:
            LOGGER.error("Check that Windows Event Log service is running")
    finally:
        # if logHandle is not None:
        # win32api.CloseHandle(logHandle)
        pass
    return


def readeventsXML(path):
    parser = evtx.PyEvtxParser(path)
    for enventOrder,event in enumerate(parser):
        datefmts=[
            "%Y-%m-%d %H:%M:%S.%f %Z",
            "%Y-%m-%d %H:%M:%S %Z"]
        for df in datefmts:
            try:
                d=datetime.strptime(
                    event['timestamp'], df).isoformat()
            except ValueError:
                continue
            break
        else:
            LOGGER.error(f"Unable to parse date '{event['timestamp']}'")
        event_dict = {
            'TimeGenerated':d 
            
        }
        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        stringInserts = []
        event_dict['EventData'] = {}
        try:
            parser="lxml"
            et = etree.fromstring(event['data']
                            .encode('utf8')
            )
            system = et.find("e:System", ns)
            event_dict['SourceName'] = system.find("e:Provider", ns).attrib['Name']
            event_dict['Id'] = int(system.find("e:EventID", ns).text)
            event_dict['EventType'] = system.find("e:Level", ns).text
            event_dict['ComputerName'] = system.find("e:Computer", ns).text            
            eventdata = et.find("e:EventData", ns)

        except etree.XMLSyntaxError as e:
            LOGGER.warning(f"{path}:{enventOrder} is damaged, using BeautifulSoup4")
            LOGGER.debug(event['data'])
            parser="bs"
            et=BeautifulSoup(event['data'],"xml")
            system = et.find("System")
            event_dict['SourceName'] = system.find("Provider")['Name']
            event_dict['Id'] = int(system.find("EventID").text)
            event_dict['EventType'] = system.find("Level").text
            event_dict['ComputerName'] = system.find("Computer").text            
            eventdata = et.find("EventData")
        
        if eventdata is not None:
            if parser=="lxml":
                it= eventdata.findall("e:Data", ns)
            else:
                it = eventdata.findAll("Data")

            for elem in it:
                try:
                    if parser=="lxml":
                        k = elem.attrib['Name']
                    else:
                        k = elem['Name']
                except KeyError:
                    # print(event['data'])
                    k = 'Data'
                    # An anomalous message, we're probably not handling it well
                    #raise Exception("Eeek!")
                v = elem.text
                if v is None:
                    v = ''
                stringInserts.append(v)
                event_dict['EventData'][k] = v
        else:  # Handle UserData and such
            # See https://eventlogxp.com/blog/the-fastest-way-to-filter-events-by-description/
            eventdata = et[1]
            for e in eventdata.iter():
                if len(e.getchildren()) == 0:
                    tag = e.tag.split("}")[1]
                    if e.text is None:
                        val = ''
                    else:
                        val = e.text
                    stringInserts.append(val)
                    event_dict['EventData'][tag] = val
        b = bunch.Bunch()
        b.SourceName = event_dict['SourceName']

        b.StringInserts = tuple(stringInserts)
        b.EventID = event_dict['Id']
        event_dict['data'] = stringInserts
        try:
            description = expandString(b)
        except SystemError as e:
            LOGGER.warning(str(e))
        event_dict['Description'] = description
        if description:
            event_dict.update(description_to_fields(description))
            first_line = description.split("\r\n")[0]
            event_dict['Short Description'] = first_line
        yield event_dict


def description_to_fields(description):
    event_dict = {}
    prefix = ''
    for l in description.split("\r\n"):
        #####
        # WHY, oh Why? Well,  Imagine the following record sample
        ###
        #             An account failed to log on.

        # Subject:
        #     Security ID:        S-1-5-21-3333333333-4444444444-5555555555-6666
        #     Account Name:       joebloggs
        #     Account Domain:     DOMAIN
        #     Logon ID:       0x8be966a

        # Logon Type:         2

        # Account For Which Logon Failed:
        #     Security ID:        NULL SID
        #     Account Name:       administrator
        #     Account Domain:     SYSEM
        ###
        # See that Security ID and Account Name are mentioned twice? So what we will do
        # is we will prefix the first one with "Subject" and 2nd one with Account For Which....
        #

        m = re.match(r"^([A-Za-z ]+):\s*$", l)
        if m:  # we've hit a prefix like "Subject:"
            prefix = m.group(1)
            continue
        if prefix and l == '':  # end of prefix
            prefix = ''
            continue

        m = re.match(r"^\t*([A-Za-z ]+):\t{1,}(.+)", l)
        if m:
            (k, v) = m.groups()
            if prefix:
                new_key = prefix + " " + k
            else:
                new_key = k
            if new_key in event_dict:
                LOGGER.warn(
                    "Key {} already in dict with value: {}".format(
                        new_key, event_dict[new_key]))
            event_dict[new_key] = v
    return event_dict


def main():
    parser = argparse.ArgumentParser(description='Parse EVTX files')
    parser.add_argument('--output', "-o", metavar='OUTPUT', type=str,
                        help='Destination, if - then STDOUT (default)', default='-')
    parser.add_argument('logfiles', metavar='LOGFILE.evtx', type=str, nargs='+',
                        help='List of logfiles to parse. Will expand wildcards.')
    parser.add_argument('--output-format', "-f", type=str, dest="format", choices=OUTPUT_FORMATS,
                        default="json",
                        help='Output format, choices are:' + ",".join(OUTPUT_FORMATS))
    parser.add_argument('--additional-dlls', type=str, dest="extradllpath",
                        help='Directory with additoinal DLLs to load (as created by dllraider)')
    parser.add_argument('--debug', "-d", action="store_true",
                        help='Debug level messages')
    parser.add_argument('--mode', help="Parsing mode: xml or native", choices=["xml", "native"],
                        default="native")

    args = parser.parse_args()

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.output == "-":
        output = sys.stdout
    else:
        output = open(args.output, "w")
    loadDLLsInCache(args.extradllpath)
    all_logs = [item for sublist in [
        glob.glob(k) for k in args.logfiles] for item in sublist]

    if args.mode == "native":
        parsefunc = readevents
    elif args.mode == "xml":
        parsefunc = readeventsXML

    counter=0
    for lf in all_logs:
        LOGGER.info("Processing {}".format(lf))
        try:
            for record in parsefunc(lf):

                if args.format == "json":
                    txt = json.dumps(record)
                    output.write(txt+"\n")
                    LOGGER.debug(txt)        
        except (pywintypes.error,RuntimeError) as e:
            LOGGER.error(str(e))
            
        counter+=1
    LOGGER.info(f"Processed {counter} out of {len(all_logs)} files")


if __name__ == '__main__':
    main()
