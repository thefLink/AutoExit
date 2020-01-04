import argparse
import ctypes
import lief
import os
import struct

from ctypes import wintypes 

fixExtensions = [".dll", ".exe", ".fpi"]

def main(traceeFolder):

    """ Find address of ExitProcess """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    kernel32.GetProcAddress.argtypes = (wintypes.HMODULE, wintypes.LPCSTR)
    addrExitProc = kernel32.GetProcAddress(kernel32._handle, b"ExitProcess")
    print("[+] Found ExitProcess at: " + hex(addrExitProc))

    code = []
    code += [0x31, 0xc0] # xor eax, eax
    code += [0x50] # push eax
    code += [0xb8] # mov eax
    code += list(struct.pack("<I", addrExitProc))
    code += [0xff, 0xd0] # call eax

    fixInFolder(traceeFolder, addrExitProc, code)
    
    
def fixInFolder(folder, exitProcess, code):    

    for file in os.listdir(folder):
     filename = os.fsdecode(file)

     if(os.path.isdir(folder + "\\" + filename)):
        fixInFolder(folder + "\\" + filename, exitProcess, code)
     
     if any(fixExtension in filename for fixExtension in fixExtensions):
        

         binary = lief.parse(folder + "\\" + filename)
         try:
             section = binary.get_section("ExitMe")
             print("[*] Fixing: " + filename)
             section.content = code

             builder = lief.PE.Builder(binary)
             builder.build()
             builder.write(folder + "\\" + filename)
              
         except:
             continue

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-traceeFolder", required=True)

    args = parser.parse_args()
    main(args.traceeFolder)
