
# Copyright (C) 2018 v3aqb

# This file is part of fwlite-cli.

# Fwlite-cli is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Fwlite-cli is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with fwlite-cli.  If not, see <https://www.gnu.org/licenses/>.

from __future__ import absolute_import, print_function, division

import os
import sys
import argparse

from .config import Config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', required=True, help="path to config file")
    parser.add_argument('-gui', action='store_true')
    args = parser.parse_args()

    if not os.path.exists(args.c):
        sys.stderr.write(f'config file {args.c} not exist!\n')
        sys.exit()

    conf = Config(args.c, args.gui)

    conf.reload()
    conf.start()


if __name__ == '__main__':
    main()
