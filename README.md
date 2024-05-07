# Dissertation Software Artefact
Artifact Related to Thomas Hearmon's 2024 Newcastle University Dissertation

## Requirements
All required libraries can be found in the requirements.txt file.

## Running the Program
Please note this program only works on Linux Operating Systems
### Linux
Open the terminal and navigate to the src folder

For me the folder is here:
```
~/PycharmProjects/time_based_stegochannels_artifact/src
```
The command to get to this is:
```
$ cd PycharmProjects\time_based_stegochannels_artifact\src
```
If it is your first time running the project you need to run the commands:
```
$ pip install pycryptodome scapy
```
You also need to run the following command to allow python to open raw sockets through the scapy library. 
Please note that this will allow anyone to open raw sockets on your system.  
```
$ sudo setcap cap_net_raw=eip /usr/bin/pythonX.X
```
Where X.X is the version of python you have installed (note the path could be different in your system)

Then run the following command:
```
$ python3 main.py
```
The program will now run in that terminal window.

You can either create your own login credentials or use the predefined admin credentials. Which are:

```
Username: ADMIN
Password: ADMIN
```
