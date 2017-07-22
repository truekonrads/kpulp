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

OUTPUT_FORMATS = "json".split(" ")
LANGID = win32api.MAKELANGID(win32con.LANG_NEUTRAL, win32con.SUBLANG_NEUTRAL)
DLLCACHE = {}


def getLogDlls(sourceName, logType):
    cachekey = logType + "/" + sourceName
    if cachekey not in DLLCACHE:

        keyName = u'SYSTEM\\CurrentControlSet\\Services\\EventLog\\{}\\{}'.format(
            logType, sourceName)
        logging.debug("Opening key {}".format(keyName))
        handle = win32api.RegOpenKey(win32con.HKEY_LOCAL_MACHINE, keyName)
        dllNames = win32api.RegQueryValueEx(
            handle, "EventMessageFile")[0].split(";")
        DLLCACHE[cachekey] = []
        for dllName in dllNames:
            dllHandle = loadDLL(dllName)
            DLLCACHE[cachekey].append(dllHandle)

    return DLLCACHE[cachekey]


def loadDLL(dllName):

    dllPath = win32api.ExpandEnvironmentStrings(dllName)
    logging.warn("Loading library {}".format(dllPath))
    dllHandle = win32api.LoadLibraryEx(
        dllPath, 0, win32con.LOAD_LIBRARY_AS_DATAFILE)
    return dllHandle


def expandString(event, logType="Security"):
    try:
        candidateDlls = getLogDlls(event.SourceName, logType)

        for dllHandle in candidateDlls:
            try:
                data = win32api.FormatMessageW(win32con.FORMAT_MESSAGE_FROM_HMODULE,
                                               dllHandle, event.EventID, LANGID, event.StringInserts)
                return data
            except win32api.error:
                pass  # not in this DLL
    except pywintypes.error:
        pass
    logging.debug("Unable to expand data for {} {}".format(
        event.SourceName, event.EventID))
    return ""


def readevents(path):
    logHandle = win32evtlog.OpenBackupEventLog("localhost", path)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    total = win32evtlog.GetNumberOfEventLogRecords(logHandle)
    logging.debug("Total number of records for {} is: {}".format(path, total))

    if "security" in path.lower():
        logType = "Security"
    elif "application" in path.lower():
        logType = "Application"
    elif "system" in path.lower():
        logType = "System"
    else:
        logging.error("Unknown log type - put something in path")
        sys.exit(-1)
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

                description = expandString(event, logType)
                if description:
                    event_dict.update(description_to_fields(description))
                    first_line = description.split("\r\n")[0]
                    event_dict['Short Description'] = first_line

                event_dict['Description'] = description
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
                logging.warn(
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
    args = parser.parse_args()

    if args.format == "csv":
        raise NotImplementedError
    if args.output == "-":
        output = sys.stdout
    else:
        output = open(args.output, "wb")

    all_logs = [item for sublist in [
        glob.glob(k) for k in args.logfiles] for item in sublist]

    for lf in all_logs:
        logging.warn("Processing {}".format(lf))

        for record in readevents(lf):

            if args.format == "json":
                txt = json.dumps(record) + "\r\n"
                output.write(txt)


if __name__ == '__main__':
    main()
