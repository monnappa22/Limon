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
@Description:  Limon Linux Sandbox - Analyses Linux Malware by performing static, dynamic and memory analysis
"""

from statan import *
from dyan import *
from meman import *
from conf import *
from optparse import OptionParser
import shutil
import time


# checking if filename and arguments are provided
if len(sys.argv) <= 1:
    print("Please give some options, type -h or --help for more information")
    sys.exit()

# adding and parsing  options
parser = OptionParser('Usage: %prog [Options] <file> [args]')

parser.add_option("-t", "--timeout", dest="timeout", help="timeout in seconds, default is 60 seconds", default="60", type="int")
parser.add_option("-i", "--internet", action="store_true", dest="internet", help = "connects to internet",  default=False)
parser.add_option("-p", "--perl", action="store_true", dest="perl", help="perl script (.pl)",  default=False)
parser.add_option("-P", "--python", action="store_true", dest="python", help="python script (.py)",  default=False)
parser.add_option("-z", "--php", action="store_true", dest="php", help="php script",  default=False)
parser.add_option("-s", "--shell", action="store_true", dest="shell_script", help="shell script",  default=False)
parser.add_option("-b", "--bash", action="store_true", dest="bash_script", help="BASH script",  default=False)
parser.add_option("-k", "--lkm", action="store_true", dest="lkm", help="load kernel module",  default=False)
parser.add_option("-C", "--ufctrace", action="store_true", dest="ufstrace", help="unfiltered call trace(full trace)", default=False)
parser.add_option("-e", "--femonitor", action="store_true", dest="femonitor", help="filtered system event monitoring", default=False)
parser.add_option("-E", "--ufemonitor", action="store_true", dest="ufemonitor", help="unfiltered system event monitoring", default=False)
parser.add_option("-m", "--memfor", action="store_true", dest="memfor", help="memory forensics", default=False)
parser.add_option("-M", "--vmemfor", action="store_true", dest="ver_memfor", help="verbose memory forensics(slow)", default=False)
parser.add_option("-x", "--printhexdump", action="store_true", dest="phexdump", help="print hex dump in call trace (both filtered and unfiltered call trace)", default=False)

(options, args) = parser.parse_args()

timeout = options.timeout
internet = options.internet
is_perl_script = options.perl
is_python_script = options.python
is_php_script = options.php
is_shell_script = options.shell_script
is_bash_script = options.bash_script
is_full_strace = options.ufstrace
is_femonitor = options.femonitor
is_ufemonitor = options.ufemonitor
is_ver_memfor = options.ver_memfor
is_lkm = options.lkm
is_memfor = options.memfor
print_hexdump = options.phexdump


if is_perl_script:
    file_path = analysis_perl_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_python_script:
    file_path = analysis_py_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_php_script:
    file_path = analysis_php_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_shell_script:
    file_path = analysis_sh_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_bash_script:
    file_path = analysis_bash_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

elif is_lkm:
    file_path = analysis_insmod_path
    params = args[0:]
    mal_file = params[0]
    file_name = os.path.basename(mal_file)
    params[0] = analysis_mal_dir + '/' + file_name
    analysis_file_path = file_path

else:
    file_path = args[0]
    mal_file = args[0]
    params = args[1:]
    os.chmod(file_path, 0777)
    file_name = os.path.basename(file_path)
    analysis_file_path = analysis_mal_dir + "/" + file_name

filter_file_name = os.path.basename(file_path)


# Check if the given file is a ELF file
if not (is_perl_script or is_python_script or is_shell_script or is_bash_script or is_php_script):
    is_elf_file = True

# creating and cleaning the report directory (used to store the reports)
new_report_dir = report_dir + "/" + file_name
if os.path.isdir(new_report_dir):
    shutil.rmtree(new_report_dir)
os.mkdir(new_report_dir)
final_report = new_report_dir + "/final_report.txt"
desk_screenshot_path = new_report_dir + "/desktop.png"
pcap_output_path = new_report_dir + "/output.pcap"
capture_output_path = new_report_dir + "/capture_output.txt"


master_ssdeep_file = report_dir + "/ssdeep_master.txt"
ascii_str_file = new_report_dir + "/strings_ascii.txt"
unicode_str_file = new_report_dir + "/strings_unicode.txt"


# Creating the master ssdeep file
if not os.path.exists(master_ssdeep_file):
    mssdeepf = open(master_ssdeep_file, "w")
    mssdeepf.write("ssdeep,1.1--blocksize:hash:hash,filename\n")
    mssdeepf.close()

f = open(final_report, 'w')


f.write( "===========================[STATIC ANALYSIS RESULTS]===========================\n\n")
#static = Static(file_path)
static = Static(mal_file)
filetype = static.filetype()
print "Filetype: %s" % filetype
f.write("Filetype: %s" % filetype)
f.write("\n")

file_size = static.get_file_size()
print "File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size)
f.write("File Size: %0.2f KB (%s bytes)" % (file_size/1024.0, file_size))
f.write("\n")

md5sum = static.md5sum()
print "md5sum: %s" % md5sum
f.write("md5sum: %s" % md5sum)
f.write("\n")

fhash = static.ssdeep()
fuzzy_hash = fhash.split(",")[0]
print "ssdeep: %s" % fuzzy_hash
f.write("ssdeep: %s" % fuzzy_hash)
f.write("\n")

if is_elf_file:
    elf_header = static.elf_header()
    print elf_header
    f.write(elf_header)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

ssdeep_compare = static.ssdeep_compare(master_ssdeep_file)
print "ssdeep comparison:"
print ssdeep_compare
print dash_lines
f.write("ssdeep comparison:")
f.write("\n")
f.write(ssdeep_compare)
f.write("\n")
f.write(dash_lines)
f.write("\n")
fm = open(master_ssdeep_file, 'a')
fm.write(fhash + "\n")
fm.close()


asc_strings = static.ascii_strings()
fs = open(ascii_str_file, 'w')
fs.write(asc_strings)
fs.close()
print "Strings:"
print "\tAscii strings written to %s" % ascii_str_file
f.write("Strings:")
f.write("\n")
f.write("\tAscii strings written to %s" % ascii_str_file)
f.write("\n")

unc_strings = static.unicode_strings()
fu = open(unicode_str_file, 'w')
fu.write(unc_strings)
fu.close()
print "\tUnicode strings written to %s" % unicode_str_file
print dash_lines
f.write("\tUnicode strings written to %s" % unicode_str_file)
f.write("\n")
f.write(dash_lines)
f.write("\n")

if is_elf_file and yara_packer_rules:
    yara_packer = str(static.yararules(yara_packer_rules))
    print "Packers:"
    print "\t" + yara_packer
    print dash_lines
    f.write("Packers:")
    f.write("\n")
    f.write("\t" + yara_packer)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

if yara_rules:
    yara_capabilities = str(static.yararules(yara_rules))
    print "Malware Capabilities and classification using YARA rules:"
    print "\t" + yara_capabilities
    print dash_lines
    f.write("Malware Capabilities and classification using YARA rules:")
    f.write("\n")
    f.write("\t" + yara_capabilities)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

print "Virustotal:\n" + "\t"
f.write("Virustotal:\n" + "\t")
f.write("\n")
avresults = static.virustotal(virustotal_key)
if avresults !=None:
    avvendors = avresults.keys()
    avvendors.sort()
    for avvendor in avvendors:
        print "\t  " + avvendor + " ==> " + avresults[avvendor]
        f.write("\t  " + avvendor + " ==> " + avresults[avvendor])
        f.write("\n")
print dash_lines
f.write(dash_lines)
f.write("\n")


if is_elf_file:
    depends = static.dependencies()
    if depends:
        print "Dependencies:"
        print depends
        print dash_lines
        f.write("Dependencies:")
        f.write("\n")
        f.write(depends)
        f.write("\n")
        f.write(dash_lines)
        f.write("\n")

    prog_header = static.program_header()
    print "Program Header Information:"
    print prog_header
    print dash_lines
    f.write("Program Header Information:")
    f.write("\n")
    f.write(prog_header)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

    sect_header = static.section_header()
    print "Section Header Information:"
    print sect_header
    print dash_lines
    f.write("Section Header Information:")
    f.write("\n")
    f.write(sect_header)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")

    syms = static.symbols()
    print "Symbol Information:"
    print syms
    print dash_lines
    f.write("Symbol Information:")
    f.write("\n")
    f.write(syms)
    f.write("\n")
    f.write(dash_lines)
    f.write("\n")


# Dynamic analysis
f.write("==========================[DYNAMIC ANALYSIS RESULTS]==========================\n\n")

# reverting to clean snapshot and starting vm
analysis_vm = Vmware(host_vmrunpath, host_vmtype, host_analysis_vmpath)
analysis_vm.set_credentials(analysis_username, analysis_password)
analysis_vm.revert(analysis_clean_snapname)
print "Starting virtual machine for analysis"
if analysis_vm.start():
    print "...done..."

# checking if internet option is given, if not starts inetsim
if not internet:
    iptables = Iptables(host_iface_to_sniff)
    print "adding ip port redirection entries"
    iptables.add_ip_port_redirect_entries()
    iptables.display_ip_port_redirect_entries()
    os.chdir(os.path.dirname(inetsim_path))   # newly added
    inetsim = Inetsim(inetsim_path)
    print "cleaning inetsim log directory"
    inetsim.clean_log_dir(inetsim_log_dir) # cleaning the log directory
    print "cleaning inetsim report directory"
    inetsim.clean_report_dir(inetsim_report_dir) # cleaning the report directory
    print "starting inetsim"
    inetsim.start()

print "Waiting for all the services to start"
time.sleep(12)

# transfer file to vm
analysis_copy_file_path = analysis_mal_dir + '/' + file_name

print "transferring file to virtual machine"
if analysis_vm.copytovm(mal_file, analysis_copy_file_path):
    print "...done..."

if is_femonitor:
    analysis_vm.execute_sysdig(analysis_sysdig_path, cap_filter, analysis_capture_out_file, filter_file_name)
    print "starting monitoring on the analysis machine"
    time.sleep(3)

if is_ufemonitor:
    analysis_vm.execute_sysdig_full(analysis_sysdig_path, analysis_capture_out_file, filter_file_name)
    print "starting monitoring on the analysis machine"
    time.sleep(3)

# starting tcpdump
net = Tcpdump(host_tcpdumppath, pcap_output_path)
print "starting Network Monitor"
net.start_tcpdump(host_iface_to_sniff, analysis_ip)
time.sleep(5)

# executing file on the analysis machine
print "executing file for " + str(timeout) + " seconds"

# run the sample using strace
if is_femonitor or is_ufemonitor:
    analysis_vm.execute_file(analysis_file_path, params)
    time.sleep(timeout)
    print "...done..."

elif is_full_strace:
    analysis_vm.execute_strace_full(analysis_strace_path, analysis_strace_out_file, print_hexdump, analysis_file_path, params)
    time.sleep(timeout)
    print "...done..."

else:
    analysis_vm.execute_strace(analysis_strace_path, analysis_strace_out_file, strace_filter, print_hexdump, analysis_file_path, params)
    time.sleep(timeout)
    print "...done..."


# stopping sysdig
if is_femonitor or is_ufemonitor:
    print "stopping monitoring"
    analysis_vm.stop_sysdig()
    time.sleep(4)

# stopping tcpdump
print "stopping Network Monitor"
net.stop_tcpdump()
time.sleep(3)


# copying sysdig capture file and strace output file to report directory

dirs = analysis_vm.list_dir(analysis_log_outpath)
log_files = analysis_vm.get_log_files_from_dir_list(dirs)
if log_files:
    for log_file in log_files:
        log_file_path = analysis_log_outpath + '/' + log_file
        report_file_path = new_report_dir + "/" + log_file
        if analysis_vm.copyfromvm(log_file_path, report_file_path):
            print "successfully copied %s to report directory " % log_file

# reading the sysdig captured file and dumping to a text file
if is_femonitor or is_ufemonitor:
    cap_name = os.path.basename(analysis_capture_out_file)
    capture_out_file = new_report_dir + '/' + cap_name
    fname, ext = os.path.splitext(cap_name)
    fname += ".txt"
    capture_out_txt_file = new_report_dir + '/' + fname
    analysis_vm.read_capture_and_dump(host_sysdig_path, capture_out_file, capture_out_txt_file, cap_format)
    print "Dumped the captured data to the %s" % capture_out_txt_file


# printing the captured data to report file

f.write("CALL TRACE ACTIVITIES\n")
f.write("=======================================\n")

if is_femonitor or is_ufemonitor:
    sysdig_trace = analysis_vm.get_calltrace_activity(capture_out_txt_file)
    print sysdig_trace
    f.write(sysdig_trace)
    f.write("\n")

else:
    strace_fname = os.path.basename(analysis_strace_out_file)
    strace_out_fname = new_report_dir + "/" + strace_fname
    strace_output = analysis_vm.get_calltrace_activity(strace_out_fname)
    print strace_output
    f.write(strace_output)
    f.write("\n")


print "capturing desktop screenshot"
if analysis_vm.capturescreen(desk_screenshot_path):
    print "done, desktop screenshot saved as %s" % desk_screenshot_path

print "suspending virtual machine"
if analysis_vm.suspend():
    print "...done..."

f.write("\n")
f.write("NETWORK ACTIVITIES\n")
f.write("=======================================\n\n")
# get and display tshark summary
f.write("DNS SUMMARY\n")
f.write("=======================================\n\n")
dns_summary = net.dns_summary()
print dns_summary
f.write(dns_summary)
f.write("\n")
f.write("TCP CONVERSATIONS\n")
f.write("=======================================\n\n")
tcp_conversations = net.tcp_conv()
print tcp_conversations
f.write(tcp_conversations)
f.write("\n")


# stopping inetsim, if internet option is not given
if not internet:
    inetsim.stop()
    time.sleep(8)  # This is requried so that all the inetsim services are stopped
    f.write("INETSIM LOG DATA\n")
    f.write("=======================================\n\n")
    inetsim_log_data = inetsim.get_inetsim_log_data()
    print inetsim_log_data
    f.write(inetsim_log_data)
    f.write("\n")
    f.write("INETSIM REPORT DATA\n")
    f.write("========================================\n\n")
    inetsim_report_data = inetsim.get_inetsim_report_data()
    print inetsim_report_data
    f.write(inetsim_report_data)
    f.write("\n")
    print "done"
    print "\n"

    print "deleting ip port redirection entries"
    iptables.delete_ip_port_redirect_entries()
    iptables.display_ip_port_redirect_entries()


if is_memfor or is_ver_memfor:

    f.write("=======================[MEMORY ANALYSIS RESULTS]=======================\n\n")

    # starting memory forensics
    print "Starting Memory Analysis using Volatility"
    vol = Volatility(py_path, vol_path, analysis_vm.get_vmmem(), mem_image_profile)

    f.write("PSLIST\n")
    f.write("=======================================\n\n")
    pslist = vol.pslist()
    print pslist
    f.write(pslist)
    f.write("\n")

    f.write("PSTREE\n")
    f.write("=======================================\n\n")
    pstree = vol.pstree()
    print pstree
    f.write(pstree)
    f.write("\n")

    f.write("Pid Hash Table\n")
    f.write("=======================================\n\n")
    pidhashtable = vol.pidhashtable()
    print pidhashtable
    f.write(pidhashtable)
    f.write("\n")

    f.write("PROCESS COMMAND LINE ARGUMENTS\n")
    f.write("=======================================\n\n")
    psaux = vol.psaux()
    print psaux
    f.write(psaux)
    f.write("\n")

    f.write("PSXVIEW\n")
    f.write("=======================================\n\n")
    psxview = vol.psxview()
    print psxview
    f.write(psxview)
    f.write("\n")

    f.write("PROCESS ENVIRONMENT\n")
    f.write("=======================================\n\n")
    psenv = vol.psenv()
    print psenv
    f.write(psenv)
    f.write("\n")

    f.write("THREADS\n")
    f.write("=======================================\n\n")
    threads = vol.threads()
    print threads
    f.write(threads)
    f.write("\n")

    f.write("NETWORK CONNECTIONS\n")
    f.write("=======================================\n\n")
    connections = vol.netstat()
    print connections
    f.write(connections)
    f.write("\n")

    f.write("INTERFACE INFORMATION\n")
    f.write("=======================================\n\n")
    ifconfig = vol.ifconfig()
    print ifconfig
    f.write(ifconfig)
    f.write("\n")

    f.write("PROCESSES WITH RAW SOCKETS\n")
    f.write("=======================================\n\n")
    raw_sockets = vol.list_raw()
    print raw_sockets
    f.write(raw_sockets)
    f.write("\n")

    f.write("LIBRARY LIST\n")
    f.write("========================================\n\n")
    lib_list = vol.library_list()
    print lib_list
    f.write(lib_list)
    f.write("\n")


    f.write("Ldrmodules\n")
    f.write("========================================\n\n")
    ldrmodules = vol.ldrmodules()
    print ldrmodules
    f.write(ldrmodules)
    f.write("\n")

    f.write("KERNEL MODULES\n")
    f.write("=========================================\n\n")
    modules = vol.lsmod()
    print modules
    f.write(modules)
    f.write("\n")

    f.write("MODULES HIDDEN FROM MODULE LIST (PRESENT IN SYSFS)\n")
    f.write("=========================================\n\n")
    chk_modules = vol.check_modules()
    print chk_modules
    f.write(chk_modules)
    f.write("\n")

    f.write("MODULES HIDDEN FROM MODULE LIST and SYSFS\n")
    f.write("=========================================\n\n")
    hidden_modules = vol.hidden_modules()
    print hidden_modules
    f.write(hidden_modules)
    f.write("\n")
    
    f.write("FILES OPENED WITHIN KERNEL\n")
    f.write("=========================================\n\n")
    krnl_opened_files = vol.kernel_opened_files()
    print krnl_opened_files
    f.write(krnl_opened_files)
    f.write("\n")

    f.write("PROCESSES SHARING CREDENTIAL STRUCTURES\n")
    f.write("=========================================\n\n")
    proc_creds = vol.check_creds()
    print proc_creds
    f.write(proc_creds)
    f.write("\n")

    f.write("KEYBOARD NOTIFIERS\n")
    f.write("=========================================\n\n")
    key_notfs = vol.keyboard_notifiers()
    print key_notfs
    f.write(key_notfs)
    f.write("\n")
    
    f.write("TTY HOOKS\n")
    f.write("=========================================\n\n")
    tty_hooks = vol.check_tty()
    print tty_hooks
    f.write(tty_hooks)
    f.write("\n")

    f.write("SYSTEM CALL TABLE MODIFICATION\n")
    f.write("=========================================\n\n")
    chk_syscall = vol.check_syscall()
    print chk_syscall
    f.write(chk_syscall)
    f.write("\n")

    f.write("BASH HISTORY\n")
    f.write("=========================================\n\n")
    bash_hist = vol.bash_history()
    print bash_hist
    f.write(bash_hist)
    f.write("\n")

    f.write("MODIFIED FILE OPERATION STRUCTURES\n")
    f.write("=========================================\n\n")
    mod_fop = vol.check_fop()
    print mod_fop
    f.write(mod_fop)
    f.write("\n")

    f.write("HOOKED NETWORK OPERTATION FUNCTION POINTERS\n")
    f.write("=========================================\n\n")
    hooked_af = vol.check_afinfo()
    print hooked_af
    f.write(hooked_af)
    f.write("\n")

    f.write("NETFILTER HOOKS\n")
    f.write("=========================================\n\n")
    netfilter_hooks = vol.netfilter()
    print netfilter_hooks
    f.write(netfilter_hooks)
    f.write("\n")


    f.write("MALFIND\n")
    f.write("=========================================\n\n")
    malfind = vol.malfind()
    print malfind
    f.write(malfind)
    f.write("\n")
    
    if is_ver_memfor:
        
        f.write("PLT HOOK\n")
        f.write("=========================================\n\n")
        plthooks = vol.plthook()
        print plthooks
        f.write(plthooks)
        f.write("\n")

        f.write("USERLAND API HOOKS\n")
        f.write("=========================================\n\n")
        apihooks = vol.apihooks()
        print apihooks
        f.write(apihooks)
        f.write("\n")
        
        f.write("INLINE KERNEL HOOKS\n")
        f.write("=========================================\n\n")
        in_kernel_hooks = vol.check_inline_kernel()
        print in_kernel_hooks
        f.write(in_kernel_hooks)
        f.write("\n")


f.close()

print "Final report is stored in %s" % new_report_dir