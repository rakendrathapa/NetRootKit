# NetRootKit

Step 1: Enabling test mode (TESTSIGNING) on Windows.
* Command(As Administrator)> bcdedit /set TESTSIGNING on
* Restart 
Helpful Link: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option

Step 2: Unzip the Driver Files to a folder.
Folder Name: NetRootKit

Step 3: Install the Driver and the User-Application.
devcon install NetRootKit.inf Root\NetRootKit

Step 4: Run the User-Application. We have 4 commands:

1. First check the connection with the kernel driver.
Format: NetRootKitController check-connection <message>
Example: NetRootKitController check-connection "Hello Kernel"
We should receive: Connected! message echoed successfully

2. Hide the IP address based on the Local-IP Address.
Format: NetRootKitController hide-ip <ip>
Example: NetRootKitController hide-ip 192.168.0.1

3. Hide the IP based on the Remote-IP Address
Format: NetRootKitController hide-remote-ip <ip>
Example: NetRootKitController hide-remote-ip 192.168.0.1

4. Hide the IP based on the local port number.
Format: NetRootKitController hide-ip <ip>
Example: NetRootKitController hide-ip 49650

5. Hide the IP based on the given PID.
Format: NetRootKitController hide-connect-pid <pid>

6. Hide the PID from the PID list.
Format: NetRootKitController hide-pid <pid>
 
