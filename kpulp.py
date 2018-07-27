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
                        except pywintypes.error, exc:
                            LOGGER.warn(
                                "Error loading {}: {}".format(dllPath, e))
        return
        from IPython import embed
        embed()

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
            except pywintypes.error, e:
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
            try:
                dllHandle = DLLCACHE[event.SourceName][dllName]
            except KeyError:
                from IPython import embed
                embed()
            data = win32api.FormatMessageW(win32con.FORMAT_MESSAGE_FROM_HMODULE,
                                           dllHandle, event.EventID, LANGID, event.StringInserts)
            return data
        elif event.SourceName not in DLLCACHE:
            LOGGER.warn("Event source not in cache".format(
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
                except SystemError, e:
                    pass
                    # print str(e)
                    # from IPython import embed
                    # embed()
    except pywintypes.error:
        pass
    LOGGER.warn("Unable to expand data for {} EventID: {}".format(
        event.SourceName, event.EventID))
    DLLMSGCACHE[cachekey] = None  # no DLLs known to expand this message
    # from IPython import embed
    # embed()
    return ""


def readevents(path):
    logHandle = win32evtlog.OpenBackupEventLog(None, path) # None=NULL means local host
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
    
    while True:
        events = win32evtlog.ReadEventLog(logHandle, flags, 0)
        if events:
            for event in events:
                event_dict = {}
                event_dict['TimeGenerated'] = time.strftime(
                    "%#c", time.localtime(int(event.TimeGenerated)))
                event_dict['SourceName'] = event.SourceName
                event_dict['Id'] = event.EventID
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

        m = re.match("^([A-Za-z ]+):\s*$", l)
        if m:  # we've hit a prefix like "Subject:"
            prefix = m.group(1)
            continue
        if prefix and l == '':  # end of prefix
            prefix = ''
            continue

        m = re.match("^\t*([A-Za-z ]+):\t{1,}(.+)", l)
        if m:
            (k, v) = m.groups()
            if prefix:
                new_key = prefix + " " + k
            else:
                new_key = k
            if new_key in event_dict:
                LOGGER.warn(
                    "Key {} already in dict with value: {} ({})".format(
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
    args = parser.parse_args()

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.output == "-":
        output = sys.stdout
    else:
        output = open(args.output, "wb")
    loadDLLsInCache(args.extradllpath)
    all_logs = [item for sublist in [
        glob.glob(k) for k in args.logfiles] for item in sublist]

    for lf in all_logs:
        LOGGER.info("Processing {}".format(lf))
        try:
            for record in readevents(lf):

                if args.format == "json":
                    txt = json.dumps(record) + "\r\n"
                    output.write(txt)
                    LOGGER.debug(txt)
        except pywintypes.error,e:
            LOGGER.error(str(e))


if __name__ == '__main__':
    main()
