# DDoSAnalysis
A denial of service attack on a web server in a school has been detected by the network administrator. A copy of a 30 minute extract of a log of the attack has been anonymised and provided to me for analysis. The file is named as DDoDRawLog.txt and contains over 2000 entries which include the source IP addresses and timestamp of the attack. 
To read in all the entries from the DDoDRawLog.txt file, analyse the IP address information in it and produce an output file with information on the sources of the DDoS attack, a program has been developed which can perform all those tasks in the correct manner. To ensure the tasks are carried out successfully, the program:
# I.	Extracts the IP addresses from the log file and writes out the IP addresses to a file avoiding duplication of IP addresses: 
•	Reading in data from a file 
•	Parsing the client IPv4 address 
•	Writing the unique IP addresses out to a file 
# II.	Classifies the IP address as A, B, C, D or E:
•	Parsing the client IPv4 address to determine which class they belong to. 
•	Displaying each IP address and its class.
# III.	Performs whois lookup: 
•	Identifying the source of the IP address, for example, using a “rdap” lookup 
•	Displaying the country of origin, Autonomous System Number(ASN) and description fields returned by the rdap lookup
# IV.	Writes information out to a report file: 
•	Writing the information gathered in about the IP addresses out to a file

