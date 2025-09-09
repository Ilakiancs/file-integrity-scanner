#!/usr/bin/env python3

"""
File Integrity Scanner
Real-time file integrity monitoring with ML-based threat detection

@author: Ilakian
"""

# Core system imports
import subprocess
import os
import sys
import pickle 
import datetime
import hashlib
import logging
import time 
import signal
from time import sleep
import dictdiffer 
from progress.bar import Bar

import getopt

def get_args(argv):
    # Parse command line arguments
    arg_input = ""
    arg_output = ""

    arg_help = "{0} -i <input directory> -o <output directory> ".format(argv[0])

    try:
        opts, args = getopt.getopt(argv[1:], "hi:o", ["help", "input=", "output="])
    except:
        print(arg_help)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print(arg_help)
            sys.exit(2)
        elif opt in ("-i", "--input"):
            arg_input = arg
            print('input directory:', arg_input)
        elif opt in ("-o", "--output"):
            arg_output = arg
            print('output directory:', arg_output)

    return [arg_input, arg_output]




    







#===============
# Colors
#===============
# Normal 
black="\033[0;30m"
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"  
blue="\033[0;34m"
purple="\033[0;35m"
cyan="\033[0;36m"
white="\033[0;37m"
# Bold
bblack="\033[1;30m"
bred="\033[1;31m"
bgreen="\033[1;32m"
byellow="\033[1;33m"
bblue="\033[1;34m"
bpurple="\033[1;35m"
bcyan="\033[1;36m"
bwhite="\033[1;37m"


#======================
#printing Banner
#======================

def banner():
    # Display application banner
    logo='''

 ██╗██╗      █████╗ ██╗  ██╗██╗ █████╗ ███╗   ██╗
 ██║██║     ██╔══██╗██║ ██╔╝██║██╔══██╗████╗  ██║
 ██║██║     ███████║█████╔╝ ██║███████║██╔██╗ ██║
 ██║██║     ██╔══██║██╔═██╗ ██║██╔══██║██║╚██╗██║
 ██║███████╗██║  ██║██║  ██╗██║██║  ██║██║ ╚████║
 ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                   
File Integrity Scanner
Real-time Security Monitoring System

Features:
- Real-time file system monitoring
- Automated change detection and alerting
- Machine learning-based malware detection
- VirusTotal API integration for threat analysis

@author: Ilakian

    '''
    print(logo)



#==========================
#Count all files in the directory and its subdirectories
#we will use it in the progress bar
#=========================

def count(SCAN_DIR):
    # Count total directories for progress tracking
    var = 0
    for dirName, subdirList, fileList in os.walk(SCAN_DIR):
        if (list_to_ignore):
            for ignore in list_to_ignore:
                if (ignore in fileList):
                    fileList.remove(ignore)
        var += 1
    return var


def scan_files(SCAN_DIR, list_to_ignore, LOG_FILE):
    # Recursively scan directory structure
    
    try:
        files = dict()
        
        # Walk directory tree with progress indicator
        with Bar('Scanning Files ...', max=count(SCAN_DIR)) as bar:
            for dirName, subdirList, fileList in os.walk(SCAN_DIR):
                
                # Filter ignored files
                if (list_to_ignore):
                    for ignore in list_to_ignore:
                        if (ignore in fileList):
                            fileList.remove(ignore)
                            
                files[str(dirName)] = fileList
                sleep(0.02)
                bar.next()

        return files
            
    except Exception as e:
        msg = "Error in scanning files and directories"
        logging.exception(msg)        


#storing hashes

def save_hash(dictionary, file, LOG_FILE):
    # Serialize hash dictionary to disk
    
    try:
        initial_scan_file = open(file, "wb")
        pickle.dump(dictionary, initial_scan_file)
        initial_scan_file.close()
        
    except Exception as e:
        msg = "Error while saving hash dictionary"
        logging.exception(msg)




# Load dictionary of hashes

def load_dict(file, LOG_FILE):
    # Load serialized hash dictionary from disk
    
    try:
        infile = open(file, 'rb')
        loaded_dict = pickle.load(infile)
        infile.close()
        return loaded_dict
        
    except Exception as e:
        log(LOG_FILE, "Error while loading hash dictionary")
    
    


# Log events

def log(log_dir, message):
    # Write timestamped events to log file
    currentDT = datetime.datetime.now()
    file = open(log_dir, "a+")
    file.write(str(message) + " --- Time: " + str(currentDT.strftime("%Y-%m-%d %H:%M:%S")) + "\n")
    file.close()
    

def log_change(log_dir, message):
    # Log changes with console output
    currentDT = datetime.datetime.now()
    file = open(log_dir, "a+")
    file.write(str(message) + " --- Time: " + str(currentDT.strftime("%Y-%m-%d %H:%M:%S")) + "\n")
    file.close()
    print(message)




# Take SHA256 of each file
# hash is taken in blocks, this is done to ensure large files doens't fail

def calculate_hash(directory, LOG_FILE):
    # Generate SHA256 hash for file integrity verification
    # Uses chunked reading for memory efficiency
    
    try:
        sha256_hash = hashlib.sha256()
        
        with open(directory, "rb") as f:
            # Read in 4KB chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
                
            return sha256_hash.hexdigest()
        
    except Exception as e:
        log(LOG_FILE, "Error calculating file hash")




# integrity FUNCTION

def integrity():
    # Main file integrity monitoring loop
    
    print("DIRECTORY TO MONITOR: {} ".format(SCAN_DIRECTORY))

    log(LOG_FILE, "Starting initial scan...")
    
    # Establish baseline file state
    INITIAL_FILE_HASHES = scan()
    save_hash(INITIAL_FILE_HASHES, SCAN_STORAGE, LOG_FILE)
    log(LOG_FILE, "Initial scan completed!")
    
    log(LOG_FILE, "Starting integrity monitoring...")
   	
    # Continuous monitoring loop
    while True:
        new_hash = scan()
        old_hash = load_dict(SCAN_STORAGE, LOG_FILE)
        
        # Detect and process changes
        for diff in list(dictdiffer.diff(old_hash, new_hash)):         
            log_change(ALERT_FILE, diff)
            malware_detection(diff)
            
        save_hash(new_hash, SCAN_STORAGE, LOG_FILE)
        sleep(sleep_time_sc)
    
    
    # start the integrity check
    log(LOG_FILE, "Starting the integrity check...")
   	
    while True:
        
        # get the file hashes
        new_hash = scan()
        
        # load the old hash
        old_hash = load_dict(SCAN_STORAGE,\
                                          LOG_FILE)
        
        # compare two dict of hashes
        for diff in list(dictdiffer.diff(old_hash, new_hash)):         
            # ALERT
            
            log_change(ALERT_FILE, diff)
            malware_detection(diff)
        # save the new hash
        save_hash(new_hash, \
                               SCAN_STORAGE,
                               LOG_FILE)
        
        # wait
        sleep(sleep_time_sc)
        



# Scan the directory tree and take hash of the files 
# Return a dictionary of hashes and file paths

def scan():
    # Scan the directory and calculate hashes for all files
    # This function gets called every few seconds to check for changes
    
    # Get dictionary of directories and files they contain
    directories = scan_files(SCAN_DIRECTORY, list_to_ignore, LOG_FILE)        
    
    # Calculate hash for each file
    file_hashes = dict()  # Empty dictionary to store results
    
    # Go through each directory
    for path, files in directories.items():
        # Look at each file in this directory
        for file in files:
            # Get the full path to the file
            file_dir = str(path) + "/" + str(file)
            
            # Calculate and store the hash of this file
            file_hashes[file_dir] = calculate_hash(file_dir, LOG_FILE)
            
    # Return dictionary with file paths and their hashes
    return file_hashes


def calculate_entropy(data):
    # Calculate Shannon entropy for data analysis
    if not data:
        return 0
    
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0
    data_len = len(data)
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * (probability.bit_length() - 1)
    
    return entropy





def malware_detection(changes):
    # Check file changes for potential malware
    change_type = changes[0]
    
    if change_type == 'change':
        file_path = changes[1]
        
        # Check file extension and size for suspicious activity
        if file_path.endswith(('.exe', '.scr', '.bat', '.com', '.pif')):
            log(ALERT_FILE, f"SUSPICIOUS: Executable file modified: {file_path}")
            
            if os.path.exists(file_path):
                file_size = os.path.getsize(file_path)
                # Check for unusually large or small executables
                if file_size > 50 * 1024 * 1024 or file_size < 1024:
                    log(ALERT_FILE, f"WARNING: Unusual file size: {file_size} bytes")
    
    elif change_type == 'add':
        # Check new files with suspicious characteristics
        for file_path in changes[2]:
            if file_path.endswith(('.exe', '.scr', '.bat', '.com', '.pif')):
                log(ALERT_FILE, f"ALERT: New executable created: {file_path}")
                
                if os.path.exists(file_path):
                    # Quick entropy check for packed executables
                    try:
                        with open(file_path, 'rb') as f:
                            data = f.read(8192)
                            if data:
                                entropy = calculate_entropy(data)
                                if entropy > 7.0:
                                    log(ALERT_FILE, f"HIGH ENTROPY: Possibly packed executable: {file_path}")
                    except Exception as e:
                        log(ALERT_FILE, f"ERROR: Could not analyze file: {file_path}")

def api_virus_total(file):
    # Call the VirusTotal script to check file online
    subprocess.call(['python3', 'virustotal.py', '-m', file])

def hand_sign(signum, frame):
    # Handle SIGINT signal gracefully
    res = input("Ctrl-c was pressed. Do you really want to exit? y/n :")
    if res == 'y':
        print("Quitting!\n", "Saving the results in {} ".format(ALERT_FILE))
        exit(1)
 
# Set up signal handler for Ctrl+C
signal.signal(signal.SIGINT, hand_sign)

# Main program entry point
if __name__ == "__main__":
    # Initialize default values
    l = []
    SCAN_DIRECTORY = '.'
    ALERT_FILE = 'alert.log'
    
    # Parse command line arguments
    l = get_args(sys.argv)
    
    # Configure monitoring parameters
    if l[0] != "":
        SCAN_DIRECTORY = l[0]
    if l[1] != "":
        ALERT_FILE = l[1]
    
    # Initialize storage and logging
    SCAN_STORAGE = 'hashes.pkl'
    LOG_FILE = 'handler.log'
    
    # Configure file exclusions
    list_to_ignore = [SCAN_STORAGE, LOG_FILE, ALERT_FILE]
    
    # Set monitoring interval
    sleep_time_sc = 4
    
    # Display current timestamp
    print(str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + "\n")
    
    # Display system banner
    banner()
    
    # Begin file integrity monitoring
    integrity()

    
