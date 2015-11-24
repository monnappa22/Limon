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
@Description:  Configuration file for Limon sandbox
"""

##############[general variables]################################
py_path = r'/usr/bin/python'
report_dir = r'/root/linux_reports'
dash_lines = "-" * 40
is_elf_file = False
virustotal_key = "enter virustotal public key here"

###############[vm variables]#####################################
host_analysis_vmpath = r'/root/virtual_machines/Ubuntu12_04/Ubuntu12_04.vmx'
host_vmrunpath = r'/usr/bin/vmrun'
host_vmtype = r'ws'
analysis_username = "enter username of the analysis machine"
analysis_password = "enter password of the analysis machine"
analysis_clean_snapname = "cleansnapshot"
analysis_mal_dir = r"/root/malware_analysis"
analysis_py_path = r'/usr/bin/python'
analysis_perl_path = r'/usr/bin/perl'
analysis_bash_path = r'/bin/bash'
analysis_sh_path = r'/bin/sh'
analysis_insmod_path = r'/sbin/insmod'
analysis_php_path = r'/usr/bin/php'


################[static analyis variables]##########################
yara_packer_rules = r'/root/yara_rules/packer.yara'
yara_rules = r'/root/yara_rules/capabilities.yara'

#################[network variables]#################################
analysis_ip = "192.168.1.150"
host_iface_to_sniff = "eth0"
host_tcpdumppath = "/usr/sbin/tcpdump"

#######################[memory anlaysis variables]##################

vol_path = r'/root/Volatility/vol.py'
mem_image_profile = '--profile=LinuxUbuntu1204x64'

######################[inetsim variables]#########################
inetsim_path = r"/usr/share/inetsim/inetsim"
inetsim_log_dir = r"/usr/share/inetsim/log"
inetsim_report_dir = r"/usr/share/inetsim/report"

######################[monitoring varibales]##########################

analysis_sysdig_path = r'/usr/bin/sysdig'
host_sysdig_path = r'/usr/bin/sysdig'
analysis_capture_out_file = r'/root/logdir/capture.scap'

cap_format = "%proc.name (%thread.tid) %evt.dir %evt.type %evt.args"
cap_filter = r"""evt.type=clone or evt.type=execve or evt.type=chdir or evt.type=open or
evt.type=creat or evt.type=close or evt.type=socket or evt.type=bind or evt.type=connect or
evt.type=accept or evt.is_io=true or evt.type=unlink or evt.type=rename or evt.type=brk or
evt.type=mmap or evt.type=munmap or evt.type=kill or evt.type=pipe"""

analysis_strace_path = r'/usr/bin/strace'
strace_filter = r"-etrace=fork,clone,execve,chdir,open,creat,close,socket,connect,accept,bind,read,write,unlink,rename,kill,pipe,dup,dup2"
analysis_strace_out_file = r'/root/logdir/trace.txt'

analysis_log_outpath = r'/root/logdir'
params = []
