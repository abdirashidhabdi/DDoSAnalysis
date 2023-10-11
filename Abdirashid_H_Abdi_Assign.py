''' Program Title: Formal Element 
    Program Developer: Abdirashid Hussein Abdi
    Date: 11/4/2020 '''

# This program reads in all the entries from DDoDRawLog.txt, analyses the IP address information and produces an output file with information on the sources of the DDoS attack.

#======== MAIN PROGRAM ====================#
def main():
    file_name = input("Enter file name with extension(.txt): ")                         # Prompt the user to enter file name
    read_fptr = open(file_name,"r")                                                     # Open file for reading
    line = read_fptr.readline()[42:54]                                                  # Read the characters in index 42 to index 54 from 1st line
    # Loop for reading characters from lines
    for l in read_fptr:
        line = line + "," + l[42:57].strip("]").strip("] ").strip("] m").strip("] mo").strip("] mod")  # Read the characters in index 42 to index 57 from 2nd line to the last line, stripping unwanted characters
    read_fptr.close()                                                                   # Close file

    ip_list = line.split(",")                                                           # Change the string data to a list
    ip_set = set(ip_list)                                                               # Convert the list to a set; to contain unique data only

    write_fptr = open("ipAddresses.txt", "w")                                           # Open a new file to write unique addresses
    # Loop through the set to output IP addresses 
    for ip in ip_set:
        write_fptr.write(ip + "\n")                                                     # Write the read IP address to the file
    write_fptr.close()                                                                  # Close file

    print(":::::::::::::::::DISPLAYING IP ADDRESSES AND THEIR CLASSES:::::::::::::::::")# Display this message on screen

    # Loop for checking IP addresses' classes
    for eachIP in ip_set:
        ip_slice = float(str(eachIP[:4]))                                               # Slice the 1st five characters from line, convert them to float & store them into a variable called 
        ip = str(check_ip_class(ip_slice, eachIP))                                      # Call function to check the class of the IP addresses
        ip = ip.strip("('").rstrip("')").replace(" '", "").lstrip("',").replace("',", "  ") # Clean the read line
        print(ip)                                                                       # Display the IP address and its class on screen

    print("\nPlease wait! Program still executing......")                               # Display this message on screen
    
    # Loop for reading through IP addresses in the set 
    for ip in ip_set:
        lookup_dict = identify_ip(ip)                                                   # Call the function identify_ip to gather info on IP addresses and store in a variable called lookup_dict
        write_out_ip_info(lookup_dict, ip)                                              # Call the function to output the data collected from IP lookup
    
    print("\n...Program completed execusion!!")
#----------------------------------------------------------------------------------------------------------------------------------------------------------#

# Function to classify IP addresses
def check_ip_class(line, ip):
    if line >= 1.0 and line <= 126.255:                                                 # Check if the first and second octet are within this range,
        return ("IP address:", ip, "Class: A")                                        # and if they are within the range, display the IP address and its class
    elif line >= 128.0 and line <= 191.255:                                             # Check if the first and second octet are within this range,
        return ("IP address:", ip, "Class: B")                                        # and if they are within the range, display the IP address and its class
    elif line >= 192.0 and line <= 223.255:                                             # Check if the first and second octet are within this range,
        return ("IP address:", ip, "Class: C")                                        # and if they are within the range, display the IP address and its class
    elif line >= 224.0 and line <= 239.255:                                             # Check if the first and second octet are within this range,
        return ("IP address:", ip, "Class: D")                                        # and if they are within the range, display the IP address and its class
    elif line >= 240.0 and line <= 254.255:                                             # Check if the first and second octet are within this range,
        return ("IP address:", ip, "Class: E")                                        # and if they are within the range, display the IP address and its class
    else:                                                                               # Otherwise,
        return ("Invalid IP address!")                                                  # Display this message

#---------------------------------------------------------------------------------------------------------------------------------------------------------#


from ipwhois import IPWhois         # Return whois lookup result as dictionary
from pprint import pprint           # Displays dictionaries very nicely

# Function to get details of the IP addresses
def identify_ip(ip):
    try:
        domain = IPWhois(ip)
        lookup_dict = domain.lookup_rdap(asn_methods=['dns','whois', 'http'])
        del lookup_dict["nir"]                                                          # Remove this key from the lookup_dict dictionary
        del lookup_dict["entities"]                                                     # Remove this key from the lookup_dict dictionary
        del lookup_dict["network"]                                                      # Remove this key from the lookup_dict dictionary
        del lookup_dict["objects"]                                                      # Remove this key from the lookup_dict dictionary
        del lookup_dict["asn_registry"]                                                 # Remove this key from the lookup_dict dictionary
        del lookup_dict["raw"]                                                          # Remove this key from the lookup_dict dictionary
        del lookup_dict["query"]                                                        # Remove this key from the lookup_dict dictionary
        
        return (lookup_dict)                                                            # Return the lookup_dict to the calling function when identify_ip function is called
    
    except Exception as e:
        print(e)
#------------------------------------------------------------------------------------------------------------------------------------------------------------#

# Function to write the information gathered on the IP addresses to a report file
def write_out_ip_info(d, ip):
    keys_list = list(d)                                                                 # Store the keys in the d dictionary passed to the dunction to a list called keys_list

    str_1 = d["asn"]                                                                    # Store the value of "asn" key in the passed dictionary to a string variable called str_1
    str_2 = d["asn_cidr"]                                                               # Store the value of "asn_cidr" key in the passed dictionary to a string variable called str_2
    str_3 = d["asn_country_code"]                                                       # Store the value of "asn_country_code" key in the passed dictionary to a string variable called str_3
    str_4 = d["asn_date"]                                                               # Store the value of "asn_date" key in the passed dictionary to a string variable called str_4
    str_5 = d["asn_description"]                                                        # Store the value of "asn_description" key in the passed dictionary to a string variable called str_5
    
    f = open("ipInfo.txt","a")                                                          # Open file for writing/appending
    f.write("*------ NOTE: Each time the program is run, it appends to the same file ------*\n")
    f.write("IP address: " + ip + "\n")                                                 # Write this to the open file
    f.write(keys_list[0] + ": " + str_1 + "\n")                                         # Write this to the open file
    f.write(keys_list[1] + ": " + str_2 + "\n")                                         # Write this to the open file
    f.write(keys_list[2] + ": " + str_3 + "\n")                                         # Write this to the open file
    f.write(keys_list[3] + ": " + str_4 + "\n")                                         # Write this to the open file
    f.write(keys_list[4] + ": " + str_5 + "\n")                                         # Write this to the open file
    f.write("#=================== Each section contains details for one IP address ===================#\n")
    f.write("\n")                                                               
    
    f.close()                                                                           # Close the file
#---------------------------------------------------------------------------------------------------------------------------------------------------------#

# Start of the program
if __name__  == "__main__":
    main()

