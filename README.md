# AutoExit

When fuzzing GUI applications, such as PDF viewers, Fuzzers do not know when to terminate the application.
Since a PDF viewer processes the input and then displays it to the user, it does not terminate and thus, 
a fuzzer has to guess when no crash happend (=hardcoded timeout).
This is highly imprecise.    

This script ensures that the PDF viewer terminates, once it is done with parsing and rendering the PDF.
To do so, it uses DynamoRIO to get a list of all executed basic blocks. Then it chooses the last basic block which:

- Was executed only once
- is >= 6 bytes (size constraint for patching)

This basic block is patched to call ExitProcess()

## Please Note

- The applied patch works only for 32 bit applications. 
- Must be run from a 32 bit python version
- The exitprocess address is hardcoded and the patch wont survive a reboot (will probably release a second script to fix that)
- Big, event based, GUI applications do not always have the same last basic block. Run the script multiple times with different inputs. 

## Usage:

```
python.exe ExitMe.py -traceeLoc "C:\Program Files (x86)\Foxit Software\Foxit Reader\FoxitReader.exe" -traceeArgv pdf-test.pdf -dynamoLoc C:\Users\flink\Desktop\DynamoRIO-Windows-7.1.0-1\DynamoRIO-Windows-7.1.0-1\bin32\ -timeout 8

[*] generating trace
[*] now parsing trace. this might take a while
        [+] chosen block:  0x002f4254
        [+] module: c:\program files (x86)\foxit software\foxit reader\foxitreader.exe
[*] checking exitme section ...
[+] found exitprocess at: 0x75c14f20
[*] creating backup of module
[+] adding new section with exitprocess() call
[*] section is at: 0x5dc2000
```
