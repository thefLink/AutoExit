import argparse
import ctypes
import glob
import lief
import os 
import shutil
import struct
import subprocess

from ctypes import wintypes 
from time import sleep

DRRUN_CALL = "%s\\drrun.exe -t drcov -nudge_kills -dump_text -- %s %s"
NUDGE_CALL = "%s\\drconfig.exe -nudge %s 0 1"

def main(traceeLoc, traceeArgv, dynamoLoc, timeout):

    trace = getTrace(traceeLoc, traceeArgv, dynamoLoc, timeout)
    finalBlockDict = trace[-1]

    bb = list(finalBlockDict.keys())[0]
    module = finalBlockDict[bb]

    print("\t[+] Chosen block: " + bb)
    print("\t[+] Module: "+ module[0])

    liefBinary, newSection = addExitSection(module)
    applyPatch(liefBinary, newSection, bb)

    """ Write patched binary to disk """
    builder = lief.PE.Builder(liefBinary)
    builder.build()
    builder.write(module[0])

    print("[+] Written patched binary")

def applyPatch(binary, newSection, bb):

    """ Patching bb to jump to new section  """
    section_absolute = binary.optional_header.imagebase + newSection.virtual_address
    print("[+] Section is at: " + hex(section_absolute))

    asm = []
    asm += ([0x68]+ list(struct.pack("<I", section_absolute))) # push addr of section
    asm += [0xc3] # ret

    binary.patch_address(int(bb,16), asm)

def addExitSection(module):

    """ Find address of ExitProcess """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = (wintypes.HMODULE, wintypes.LPCSTR)
    addrExitProc = kernel32.GetProcAddress(kernel32._handle, b"ExitProcess")
    print("[+] Found ExitProcess at: " + hex(addrExitProc))

    print("[*] Creating backup of module")
    shutil.copyfile(module[0], ".\\orig_" + module[0].split("\\")[-1])
     
    binary = lief.parse(module[0])
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE

    code = []
    code += [0x31, 0xc0] # xor eax, eax
    code += [0x50] # push eax
    code += [0xb8] # mov eax
    code += list(struct.pack("<I", addrExitProc))
    code += [0xff, 0xd0] # call eax

    try:
        newSection = binary.get_section("ExitMe")
        newSection.content = code
        print("[+] Found ExitMe section, rewriting ExitProcess() just in case")
    except:
        print("[+] Adding new section with ExitProcess() call")
        newSection = lief.PE.Section("ExitMe")
        newSection.content = code
        newSection.characteristics = lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
        newSection = binary.add_section(newSection)

    return binary, newSection

def getTrace(traceeLoc, traceeArgv, dynamoLoc, timeout):

    print ("[*] Generating Trace")
    exePath = traceeLoc.split("\\")[-1]

    """ Start DynamoRIO to create a BB trace """
    procTracer = subprocess.Popen(
            DRRUN_CALL % (
                    dynamoLoc,
                    "\"" + traceeLoc + "\"",
                    traceeArgv
                    )
                , shell=True
            )

    """ Give the process some time to handle the input """
    sleep(int(timeout))

    """ Assuming that the GUI process wont terminate itself. Nudge it """
    procNudger = subprocess.Popen(
            NUDGE_CALL % (
                dynamoLoc,
                exePath
                ),
            shell = True
        )
    procNudger.wait()
    procTracer.kill()

    """ Find the created .log file """
    for traceFile in glob.glob("*.log"):
        trace = _parseTrace(traceFile)
        os.remove(traceFile)
        return trace

def _parseTrace(trace):

    print("[*] Now parsing trace. This might take a while")

    """ Parse the created logfile """
    traceRaw = open(trace, "r").read().split("\n")[4:]
    modules = {}
    bbList = []

    """ 
        Build a list of modules which were traced. 
        Kick out modules we do not care about
    """
    for moduleLine in traceRaw:

        if "C:\\Windows\\" in moduleLine or "dynamo" in moduleLine:
            continue
        if "BB Table:" in moduleLine:
            break

        moduleLine = moduleLine.split(",")
        modules[int(moduleLine[0])] = [moduleLine[8][2:], moduleLine[2]]

    """ Build a list of basic blocks and the corresponding modules """
    for bbLine in traceRaw:
        # Skip over module description
        if not "module[" in bbLine:
            continue

        bbLine = bbLine.split(":")
        moduleId = int(bbLine[0][7:-1])
        bbLine = bbLine[1].split(",")

        if moduleId in modules:
            if int(bbLine[1]) < 6:
                # The bb is too small to patch :/
                continue

            bb = {bbLine[0]:modules[moduleId]}
            if bb not in bbList:
                bbList.append({bbLine[0]:modules[moduleId]})

    return bbList

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-traceeLoc", required=True)
    parser.add_argument("-traceeArgv", required=True)
    parser.add_argument("-dynamoLoc", required=True)
    parser.add_argument("-timeout", required=True)

    args = parser.parse_args()
    main(args.traceeLoc, args.traceeArgv, args.dynamoLoc, args.timeout)
