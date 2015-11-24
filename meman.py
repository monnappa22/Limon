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
@Description:  Memory Analysis Module
"""

import subprocess

############################[memmory analysis class]####################################

class Volatility:
    def __init__(self, python_path, vol_path, mem_file, profile):
        self.mem_file = mem_file
        self.profile = profile
        self.volatility = vol_path
        self.python = python_path
        
    def run_cmd(self, cmd, args=[]):
        pargs = [self.python, self.volatility, self.profile, '-f', self.mem_file, cmd]
        if len(args):
            pargs.extend(args)
        proc = subprocess.Popen(pargs, stdout=subprocess.PIPE)
        return proc.communicate()[0]
    
    def psxview(self):
        return self.run_cmd('linux_psxview')
    
    def pslist(self):
        return self.run_cmd('linux_pslist')
    
    def pidhashtable(self):
        return self.run_cmd('linux_pidhashtable')
    
    def pstree(self):
        return self.run_cmd('linux_pstree')

    def psaux(self):
        return self.run_cmd('linux_psaux')

    def psenv(self):
        return self.run_cmd('linux_psenv')

    def threads(self):
        return self.run_cmd('linux_threads')

    def netstat(self):
        args = ["-U"]
        return self.run_cmd('linux_netstat', args)

    def ifconfig(self):
        return self.run_cmd('linux_ifconfig')

    def list_raw(self):
        return self.run_cmd('linux_list_raw')

    def library_list(self):
        return self.run_cmd('linux_library_list')

    def ldrmodules(self):
        return self.run_cmd('linux_ldrmodules')

    def lsmod(self):
        return self.run_cmd('linux_lsmod')

    def check_modules(self):
        return self.run_cmd('linux_check_modules')

    def hidden_modules(self):
        return self.run_cmd('linux_hidden_modules')

    def kernel_opened_files(self):
        return self.run_cmd('linux_kernel_opened_files')

    def check_creds(self):
        return self.run_cmd('linux_check_creds')

    def keyboard_notifiers(self):
        return self.run_cmd('linux_keyboard_notifiers')

    def check_tty(self):
        return self.run_cmd('linux_check_tty')

    def check_syscall(self):
        return self.run_cmd('linux_check_syscall')

    def bash_history(self):
        return self.run_cmd('linux_bash')

    def check_fop(self):
        return self.run_cmd('linux_check_fop')

    def check_afinfo(self):
        return self.run_cmd('linux_check_afinfo')

    def netfilter(self):
        return self.run_cmd('linux_netfilter')

    def check_inline_kernel(self):
        return self.run_cmd('linux_check_inline_kernel')

    def malfind(self):
        return self.run_cmd('linux_malfind')

    def plthook(self):
        return self.run_cmd('linux_plthook')

    def apihooks(self):
        return self.run_cmd('linux_apihooks')



    
######################################[end of memory analysis class]#########################
