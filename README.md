# NetRootKit

## Project Name
1. **NetRootKit** - Kernel Driver that currently supports following features:
> + Hooks to the GetTCPTable() and GetTCPTable2 APIs provided by nsiproxy. Enables to hide the TCP connection based on different parameters given.
> + Enables to hide the Process ID.

2. **NetRootKitController** - User-mode application that interacts with the NetRootKit driver. Sends the commands to execute different functionalities supported by the driver.

3. **GetTCPConnections** -  Test application that calls GetTCPTable() and GetTCPTable2() APIs. Used to verify our results.


## Installing the kernel driver. (Windows 10 x64)
### Kernel Driver: NetRootKit
+ **Step 1: Enabling test mode (TESTSIGNING) on Windows.**
 > + Command(As Administrator)> bcdedit /set TESTSIGNING on
 > + Restart 
 > + Helpful Link: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option


+ **Step 2: Build the NetRootKit project. Copy the content of the Driver Files to a folder.**
 > + Example Folder Name: NetRootKit


+ **Step 3: Install the Driver and the User-Application**
 > + Driver Install: devcon install NetRootKit.inf Root\NetRootKit
 > + Application Name: NetRootKitController


## Application: NetRootKitController

### Commands

1. Check the connection with the kernel driver.<br>
 **Format:** NetRootKitController check-connection \<message\> <br>
 **Example:** NetRootKitController check-connection "Hello Kernel"
 > OUTPUT: Connected! message echoed successfully
 

2. Hide the IP address based on the Local-IP Address.<br>
**Format:** NetRootKitController hide-ip \<ip\> <br>
**Example:** NetRootKitController hide-ip 192.168.0.1

3. Hide the IP based on the Remote-IP Address<br>
**Format**: NetRootKitController hide-remote-ip \<ip\> <br>
**Example**: NetRootKitController hide-remote-ip 192.168.0.1

4. Hide the IP based on the local port number<br>
**Format**: NetRootKitController hide-ip \<ip\> <br>
**Example**: NetRootKitController hide-ip 49650

5. Hide the IP based on the given PID.<br>
**Format**: NetRootKitController hide-connect-pid \<pid\> <br>
**Example**: NetRootKitController hide-connect-pid 7756

6. Hide the IP based on the Process Name.<br>
**Format**: NetRootKitController hide-connect-process \<process_name\>  <br>
**Example**: NetRootKitController hide-connect-process "anyservice.exe"

7. Hide the PID from the PID list.<br>
**Format**: NetRootKitController hide-pid \<pid\>  <br>
**Example**: NetRootKitController hide-pid 7756

8. Disable Screen Capture Protection by Hooking SetWindowDisplayAffinity in Kernel.
**Format**: NetRootKitController disable-window-capture \<pid\>  <br>
**Example**: NetRootKitController disable-window-capture 7756

## Application: GetTCPConnections
| Commands | Description |
|---|---|
| 1. GetTCPConnections gettcptable1  |        // Calls Win32 API GetTCPTable() to get the TCP Connection details.|
| 2. GetTCPConnections gettcptable2  |     // Calls Win32 API GetTCPTable2() to get the TCP connection details.|
