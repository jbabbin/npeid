Clone files from the site malforge.com 
this is related to this page on using Npeid to detect packers in network streams 

The files include 
- npeid.py -- this is the script 
- npeid_orig.zip -- this is the original files from the site 
- README.txt -- this is the readme for the npeid file 
- UserDB.txt -- peid packer database file 
- pefile-1.2.10-63.tar.gz -- dependency file 
- pynids-0.5.tar.gz -- dependency file 

-----------------------------

Detecting Packers in Network Streams with Pynids and Pefile
Submitted by famousjs on Tue, 05/19/2009 - 21:59

To step away from using snort as a base for detecting binary packers, I decided to go with a more direct approach and use a library that handled stream reassembly within python. I then simply took the data once the connection had closed, and scanned the data with PeFile. The python script, which I call nPEiD (network peid), can either scan a pcap if passed in as an argument, or sniff on an interface (default is eth0).

Example Output:

famousjs@youbantoo:~/npeid$ ./npeid.py out.pcap
['UPX 2.90 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser']

Download: http://www.malforge.com/npeid/npeid.zip

*UPDATE - Added http gzip encoding, and FTP handling
Old located at npeid/npeid_orig.zip

-Added '-e' option to extract and save binaries.

    famousjs's blog



