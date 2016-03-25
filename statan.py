# Limon
# Copyright (C) 2015 Monnappa
#
# This file is part of Limon.
#
# Limon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Limon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Limon.  If not, see <http://www.gnu.org/licenses/>.


"""
@author:       Monnappa K A
@license:      GNU General Public License 3.0
@contact:      monnappa22@gmail.com
@Description:  Static Analysis Module
"""

import magic
import hashlib
import json
import urllib2
import urllib
import sys
import os
import yara
import subprocess


class Static:

    def __init__(self, mal_file):
        self.file = mal_file
        self.md5 = ""

    def filetype(self):
        if os.path.exists(self.file):
            try:
                m = magic.open(magic.MAGIC_NONE)
                m.load()
                ftype = m.file(self.file)
                return ftype
            except AttributeError:
                ftype = magic.from_file(self.file)
                return ftype    
        else:
            print "No such file or directory:", self.file
            sys.exit()

    def get_file_size(self):
        fr = open(self.file, 'rb')
        size = len(fr.read())
        fr.close()
        return size

    def md5sum(self):
        if os.path.exists(self.file):
            f = open(self.file, 'rb')
            m = hashlib.md5(f.read())
            self.md5 = m.hexdigest()
            return self.md5
        else:
            print "No such file or directory:", self.file
            sys.exit()

    def yararules(self, rulesfile):
        rules = yara.compile(rulesfile)
        matches = rules.match(self.file)
        return matches

    def virustotal(self, key):
        url = "https://www.virustotal.com/api/get_file_report.json"
        md5 = self.md5
        parameters = {'resource' : md5, "key" : key}
        encoded_parameters = urllib.urlencode(parameters)
        try:
            request = urllib2.Request(url, encoded_parameters)
            response = urllib2.urlopen(request)
            json_obj = response.read()
            json_obj_dict = json.loads(json_obj)
            if json_obj_dict['result'] ==0:
                print "\t  " + "No match found for " + self.md5
            else:
                avresults = json_obj_dict['report'][1]
                return avresults

        except urllib2.URLError as error:
            print "Cannot get results from Virustotal: " + str(error)

    def ssdeep(self):
        fhash = subprocess.check_output(["ssdeep", self.file])
        splitted = fhash.split("\n")
        return splitted[1]

    def ssdeep_compare(self, master_ssdeep_file):
        output = subprocess.check_output(["ssdeep", "-m", master_ssdeep_file, self.file])
        return output

    def ascii_strings(self):
        output = subprocess.check_output(["strings", "-a", self.file])
        return output

    def unicode_strings(self):
        output = subprocess.check_output(["strings", "-a", "-el", self.file])
        return output

    def dependencies(self):
        try:
            output = subprocess.check_output(["ldd", self.file])
            return output
        except:
            pass

    def elf_header(self):
        output = subprocess.check_output(["readelf","-h",self.file])
        return output

    def program_header(self):
        output = subprocess.check_output(["readelf","-l",self.file])
        return output

    def section_header(self):
        output = subprocess.check_output(["readelf","-S",self.file])
        return output

    def symbols(self):
        output = subprocess.check_output(["readelf","-s",self.file])
        return output

