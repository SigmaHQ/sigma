#!/usr/bin/env python3

import os
import shutil
import sys
import threading
import time
import requests


def spin_progress_bar():
    animation = "|/-\\"
    idx = 0
    while spinning:
        progress = animation[idx % len(animation)]
        print(f"In progress [{progress}]", end="\r")
        idx += 1
        time.sleep(0.05)  # Adjust the sleep duration to control the speed of the progress bar

def find_and_copy_files(root_dir, pattern, destination_base, techniques_list):
    for root, dirs, files in os.walk(root_dir):
        for filename in files:
            file_path = os.path.join(root, filename)

            # Check if the tactic pattern string exists inside the file
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    file_content = file.read()
                    if pattern in file_content:
                        # Extract the folder name based on the pattern
                        destination_folder = search_patterns_list[pattern]+'-'+pattern
                        # Create the destination folder if it doesn't exist
                        destination_path = os.path.join(destination_base+'/tactics', destination_folder)
                        os.makedirs(destination_path, exist_ok=True)

                        # Copy the file to the destination folder
                        shutil.copy(file_path, destination_path)

                        # Do the same before considering techniques.
                        for t in techniques_list:
                            if t.lower() in file_content:
                                destination_folder2 = t.replace('.', '_')
                                destination_path2 = os.path.join(destination_base+'/techniques', destination_folder2)
                                os.makedirs(destination_path2, exist_ok=True)
                                shutil.copy(file_path, destination_path2)
          
            except UnicodeDecodeError as e:
                print(f"Error decoding file {file_path}: {e}")



if __name__ == "__main__":

    script_directory = os.path.dirname(os.path.realpath(__file__))
    root_directory = script_directory+'/../../rules'  
    destination_base_directory = script_directory+'/../../rules/mitre'  

    search_patterns_list = {
        "reconnaissance":"TA0043",
        "resource_development":"TA0042",
        "initial_access":"TA001",
        "execution":"TA002",
        "persistence":"TA003",
        "privilege_escalation":"TA004",
        "defense_evasion":"TA005",
        "credential_access":"TA006",
        "discovery":"TA007",
        "lateral_movement":"TA008",
        "collection":"TA009",
        "command_and_control":"TA0011",
        "exfiltration":"TA0010",
        "impact":"TA0040"
    }

    techniques_list = []

    # Get all techniques from MITRE ATT&CK JSON file
    # https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

    response = requests.get('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json').json()
    for item in response['objects']:
        if 'type' in item:
            if 'attack-pattern' in item['type']:
                technique = (item['external_references'][0]['external_id']).split('.')[0]
                techniques_list.append(technique)


    # Initialize the spin progress bar
    spinning = True
    # Start the spin progress bar in a separate thread
    spin_thread = threading.Thread(target=spin_progress_bar)
    spin_thread.start()
    print("Process started")

    # Organize the Sigma rules in folder by Tactics and Techniques
    for search_pattern in search_patterns_list:
        find_and_copy_files(root_directory, search_pattern, destination_base_directory, techniques_list)

    # End the spin progress bar
    spinning = False
    spin_thread.join()
    sys.stdout.write("Process completed\n")
    sys.stdout.flush() 