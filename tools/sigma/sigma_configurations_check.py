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

def main():
    list_backend =[]
    for backend in sorted(backends.getBackendList(), key=lambda backend: backend.identifier):
        list_backend.append(backend.identifier)

    print(f"Valid backend name are {list_backend}")
    print('result tab:')
    print('|Name file|Backend|check')
    print('|---|---|---')

    valid = 0
    empty = 0
    faulty = 0
    yml_files =Path('config/').glob("*.yml")
    for yml in yml_files:
       with yml.open("r",encoding="UTF-8") as f:
           data = ruamel.yaml.load(f,Loader=ruamel.yaml.RoundTripLoader)
           if 'backends' in data:
               for backend in data['backends']:
                   if backend in list_backend:
                       print(f"|{yml.name:45} | {backend:30} | OK ")
                       valid += 1
                   else:
                       print(f"|{yml.name:45} | {backend:30} | NOK")
                       faulty += 1
           else:
              msg = "no backend set"
              print(f"|{yml.name:45} | {msg:30} | -  ")
              empty += 1

    print('Summary')
    print(f'Valid : {valid}  Invalid : {faulty} No Backend : {empty}')

if __name__ == "__main__":
    main()
