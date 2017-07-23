import logging
import re
import argparse
# requires python-registry
from Registry import Registry
from Registry.Registry import RegistryKeyNotFoundException
import sys
import os
from shutil import copyfile
SOURCE_CHOICES = "hive live".split(" ")
LOGGER = logging.getLogger("kpulp")
LOGGER.setLevel(logging.INFO)
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


def expand(path, root):
    # windir

    if root.endswith("\\"):
        root += "\\"
    systemroot = os.path.join(root, r"\Windows")
    if "\\" not in path:
        s = os.path.join(systemroot, "system32", path)
    else:
        s = re.sub(r"^C:", root, path, flags=re.I)
        s = re.sub("(%systemroot%|%windir%)", systemroot, s, flags=re.I)
        if '%' in s:
            logging.error("Can't expand %s".format(path))
            sys.exit(-1)
        # print s
    return s


def main():
    parser = argparse.ArgumentParser(
        description='Raid a system or image for message DLLs ')
    parser.add_argument('--reg', metavar='REGSOURCE', type=str,
                        help='Source of registry', required=True)
    parser.add_argument('--root', metavar='PATH', type=str,
                        help='root of system to raid', required=True)
    parser.add_argument('--output', "-o", metavar='OUTPUT', type=str,
                        help='Destination directory', required=True)
    parser.add_argument('--source', "-s", type=str, choices=SOURCE_CHOICES,
                        default="hive",
                        help='Data source choices are:' + ",".join(SOURCE_CHOICES))
    parser.add_argument('--debug', "-d", action="store_true",
                        help='Debug level messages')
    args = parser.parse_args()

    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.source == "hive":
        reg = Registry.Registry(args.reg)
        candidate_sets = []
        for sk in reg.root().subkeys():
            if "ControlSet" in sk.path():
                candidate_sets.append(sk.path().split("\\")[-1])
        # print candidate_sets
        for cs in candidate_sets:
            try:
                logkey = reg.open(
                    u'{}\\Services\\EventLog'.format(cs))
                LOGGER.debug(
                    "Found a suitable key at: {}".format(logkey.path()))
                break
            except RegistryKeyNotFoundException:
                pass
        else:
            LOGGER.error(
                "Can't find suitable keys. Are you sure you have the SYSTEM hive?")
            sys.exit(-1)

        for logType in logkey.subkeys():
            LOGGER.debug("Exploring logtype {}".format(logType.path()))
            for source in logType.subkeys():
                LOGGER.debug("Exploring source {}".format(source.path()))
                shortSource = source.path().split("\\")[-1]
                for v in source.values():
                    if v.name() == "EventMessageFile":
                        for dllName in v.value().split(";"):
                            if dllName.lower().endswith(".exe"):
                                LOGGER.debug(
                                    "Skipping {} as it's an exe".format(dllName))
                                continue
                            LOGGER.info("Found a suitable DLL {} for source {}".format(
                                dllName, shortSource))
                            destdir = os.path.join(args.output, shortSource)
                            if not os.path.exists(destdir):
                                os.mkdir(destdir)
                            sourcepath = expand(dllName, args.root)
                            destpath = os.path.join(
                                destdir, sourcepath.split("\\")[-1])
                            if not os.path.exists(destpath):
                                LOGGER.info("Copying {} to {}".format(
                                    sourcepath, destpath))
                                try:
                                    copyfile(sourcepath, destpath)
                                except IOError, e:
                                    logging.warn("Error while copying {}: {}".format(sourcepath,str(e)))


if __name__ == '__main__':
    main()
