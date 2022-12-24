#!/bin/bash
# Copyright 2022 Tim Shelton
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


if [ $# -ne 3 ]; then
    echo "Usage: $0 <target> <target config> <output file>"
    echo "Ex: $0 hawk ./tools/config/hawk.yml output.txt"
    exit 1
fi

FILEDIFF=$(git fetch && git diff --name-only ..origin | egrep "rules/" )
cd ..
echo "Updating ${FILEDIFF}"
git pull origin master
python3 ./tools/sigmac --target $1 -c $2 ${FILEDIFF} > $3
E=$(pwd)
cd -

echo "Output file can be found in $E"
