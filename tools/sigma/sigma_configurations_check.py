#!/usr/bin/env python3
# A simple Sigma Configurations checker
# Copyright frack113

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sigma.backends.discovery as backends
import ruamel.yaml
from pathlib import Path
from argparse import ArgumentParser
import sys
import csv
    
def main():
    argparser = ArgumentParser(description="A simple Sigma Configurations checker")
    argparser.add_argument("--verify", "-V", action="store_true", help="Verify if configuration file have valid backend name")
    argparser.add_argument("--sumary", "-s", action="store_true", help="Give some information.")
    argparser.add_argument("--error", "-e", action="store_true", help="Exit with error code 10 on verification failures.")
    argparser.add_argument("--output", "-o", default=None, help="Output csv file")
    args = argparser.parse_args()
    
    passed = True
    
    list_backend =[]
    for backend in sorted(backends.getBackendList(), key=lambda backend: backend.identifier):
        list_backend.append(backend.identifier)

    if args.sumary: 
        print(f"Backend found :\n{list_backend}\n")

    if args.verify:
        csv_lst = []
        valid = 0
        empty = 0
        faulty = 0
        yml_files =Path('config/').glob("*.yml")
        for yml in yml_files:
            print(f"Check configurations file : {yml.name}")
            with yml.open("r",encoding="UTF-8") as f:
                data = ruamel.yaml.load(f,Loader=ruamel.yaml.RoundTripLoader)
                if 'backends' in data:
                    for backend in data['backends']:
                        if backend in list_backend:
                            csv_lst.append([yml.name,backend,'OK'])
                            valid += 1
                        else:
                            csv_lst.append([yml.name,backend,'NOK'])
                            faulty += 1
                            passed = False
                else:
                    csv_lst.append([yml.name,"no backends section",'-'])
                    empty += 1
                    #passed = False 
                    #Should not be but not sure
            
        if args.sumary: 
            print('-------')
            print('Summary')
            print(f'Valid backend name: {valid}\nInvalid backend name: {faulty}\nFile with no Backend: {empty}')
            print('-------')

        if args.output:
            with open(args.output, 'w', newline='') as csvfile:
                spamwriter = csv.writer(csvfile, delimiter=';',quotechar='|', quoting=csv.QUOTE_MINIMAL)
                spamwriter.writerow(['Configurations Name','Backend Name','Result'])
                for row in csv_lst:
                    spamwriter.writerow(row)
                
        if not passed:
            print("**************************************")
            print("Some Configurations file are not valid")
            print("**************************************")
            if args.error:
                exit(10)
                

if __name__ == "__main__":
    main()
