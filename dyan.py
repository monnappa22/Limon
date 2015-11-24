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
@Description:   Dynamic Analysis Module
"""

import subprocess
import sys
import os
import glob
import re
import psutil

#############################[inetsim class]#########################################


class Inetsim:
    def __init__(self, inetsim_path):
        self.inetsim_path = inetsim_path
        self.proc = None
        self.log_dir = ""
        self.report_dir = ""

    def clean_log_dir(self, log_dir):
        self.log_dir = log_dir
        current_dir = os.getcwd()
        os.chdir(self.log_dir)
        log_files = glob.glob('*')
        for log_file in log_files:
            if os.path.isfile(log_file):
                os.remove(log_file)
        os.chdir(current_dir)

    def clean_report_dir(self, report_dir):
        self.report_dir = report_dir
        current_dir = os.getcwd()
        os.chdir(self.report_dir)
        report_files = glob.glob('*')
        for report_file in report_files:
            if os.path.isfile(report_file):
                os.remove(report_file)
        os.chdir(current_dir)

    def start(self):
        self.proc = subprocess.Popen([self.inetsim_path])

    def stop(self):
        processes = psutil.process_iter()
        for proc in processes:
            if "inetsim_main" in proc.name():
                proc.terminate()

    # below is the old code to stop inetsim service
    '''
    def stop(self,  pid):
        os.kill(pid,  signal.SIGINT)

    def stop(self):
        if self.proc!=None and self.proc.poll() == None:
            self.proc.terminate()
    '''

    def get_inetsim_log_data(self):
        service_log = self.log_dir + "/service.log"
        log_data = open(service_log).read()
        return log_data

    def get_inetsim_report_data(self):
        report_data = ""
        report_files = glob.glob(self.report_dir + "/*")
        for report_file in report_files:
            f = open(report_file)
            report_data += f.read()
            f.close()
        return report_data
##############################[end of inetsim class]###################################

##############################[vmware class] ##########################################


class Vmware:

    def __init__(self, host_vmrun_path, host_vmtype, vmpath):
        self.host_vmrun_path = host_vmrun_path
        self.host_vmtype = host_vmtype
        self.vmpath = vmpath
        self.username = ""
        self.password = ""

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def revert(self,snapshot):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "revertToSnapshot", self.vmpath, snapshot], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

    def start(self):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "start", self.vmpath], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program!!!"
            sys.exit()
        else:
            return 1

    def copytovm(self, src, dst):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "copyFileFromHostToGuest", self.vmpath, src, dst], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

    def copyfromvm(self, src, dst):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "copyFileFromGuestToHost", self.vmpath, src, dst], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

    def capturescreen(self, dst):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "captureScreen", self.vmpath,dst], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

    def suspend(self):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "suspend", self.vmpath], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

    def get_vmmem(self):
        dir_name = os.path.dirname(self.vmpath)
        cur_dir = os.getcwd()
        os.chdir(dir_name)
        files = glob.glob("*.vmem")
        for each_file in files:
            if "Snapshot" not in each_file:
                mem_file = each_file
        vmmem_path = os.path.join(dir_name, mem_file)
        os.chdir(cur_dir)
        return vmmem_path

    def stop(self):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "stop", self.vmpath], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        if vm_stdout:
            print vm_stdout
            print "Exiting the program"
            sys.exit()
        else:
            return 1

# List directory in guest
    def list_dir(self, dir_name):
        proc = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "listDirectoryInGuest", self.vmpath, dir_name], stdout=subprocess.PIPE)
        vm_stdout = proc.communicate()[0]
        dirs = vm_stdout.split("\n")
        return dirs

# get .log, .txt and .csv related to dtrace and nori from log directory
    def get_log_files_from_dir_list(self, dir_list):
        log_files = []
        for each_file in dir_list:
            value = each_file.find(".scap")
            value1 = each_file.find(".txt")
            if value != -1 or value1 != -1:
                log_files.append(each_file)
        return log_files

    def list_process_guest(self):
        listprocess = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "-gu", self.username, "-gp", self.password, "listProcessesInGuest", self.vmpath], stdout=subprocess.PIPE)
        processes = listprocess.communicate()[0]
        process_list = processes.split("\r\n")
        for process in process_list:
            print process

    def stop_sysdig(self):
        regexp = re.compile(r'pid=(?P<pid>\d+).*sysdig')
        listprocess = subprocess.Popen([self.host_vmrun_path, "-T", self.host_vmtype, "-gu", self.username, "-gp", self.password, "listProcessesInGuest", self.vmpath], stdout=subprocess.PIPE)
        processes = listprocess.communicate()[0]
        process_list = processes.split("\r\n")
        for process in process_list:
            match = regexp.search(process)
            if match:
                pid = match.group('pid')
        subprocess.check_call([self.host_vmrun_path, "-T", self.host_vmtype, "-gu", self.username, "-gp", self.password, "killProcessInGuest", self.vmpath, pid])

    def execute_file(self, mal_file, args):
        cmd = [self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-nowait', '-activeWindow', '-interactive',
                               mal_file]
        cmd.extend(args)
        subprocess.check_call(cmd)

    def execute_sysdig(self, sysdig_file, cap_filter, cap_out_file, filter_file_name):
        cap_filter = cap_filter + " " + "and (proc.name=" + filter_file_name + " " + "or proc.aname=" + filter_file_name + ")"
        subprocess.check_call([self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               sysdig_file, cap_filter, "-w", cap_out_file])

    def execute_sysdig_full(self, sysdig_file, cap_out_file, filter_file_name):
        cap_filter = "proc.name=" + filter_file_name + " " + "or proc.aname=" + filter_file_name
        subprocess.check_call([self.host_vmrun_path, "-T", self.host_vmtype, "-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               sysdig_file, cap_filter, "-w", cap_out_file])


    def execute_strace(self, strace_path, strace_out_file, strace_filter, print_hexdump, mal_file, args):
        if print_hexdump:
            cmd = [self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               strace_path, "-o", strace_out_file, strace_filter, "-s", "64", "-eread=all", "-ewrite=all", "-f", mal_file]
        else:
            cmd = [self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               strace_path, "-o", strace_out_file, strace_filter, "-s", "216", "-f", mal_file]

        cmd.extend(args)
        subprocess.check_call(cmd)

    def execute_strace_full(self, strace_path, strace_out_file, print_hexdump, mal_file, args):
        if print_hexdump:
            cmd = [self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               strace_path, "-o", strace_out_file, "-s", "64", "-eread=all", "-ewrite=all", "-f", mal_file]
        else:
            cmd = [self.host_vmrun_path, "-T", self.host_vmtype,"-gu", self.username, "-gp", self.password, "runProgramInGuest", self.vmpath, '-noWait', '-activeWindow', '-interactive',
                               strace_path, "-o", strace_out_file, "-s", "216", "-f", mal_file]
        cmd.extend(args)
        subprocess.check_call(cmd)

    def read_capture_and_dump(self, host_sysdig_path, capture_out_file, capture_out_txt_file, cap_format):
        cap_format = '"' + cap_format + '"'
        cmd = host_sysdig_path + " " + "-p" + cap_format + " " + "-r" + " " + capture_out_file + " > " + capture_out_txt_file
        p = subprocess.Popen(cmd, shell=True)
        p.wait()

    def get_calltrace_activity(self, outfile_path):
        results = open(outfile_path).read()
        return results



#######################################[end of vmware class]###################################

########################################[tshark class]#########################################

class Tshark:
    def __init__(self, tshark_path, out_pcap):

        if not os.path.isfile(tshark_path):
            print "cannot find tshark in %s"  % tshark_path
            print "Exiting the program"
            sys.exit()

        self.tshark_path = tshark_path
        self.out_pcap = out_pcap
        self.proc = None

    def start_tshark(self, iface, ip):
        self.proc = subprocess.Popen([self.tshark_path, '-i', iface, '-w', self.out_pcap, '-f', 'host %s' % ip])

    def stop_tshark(self):
        if self.proc != None:
            self.proc.terminate()

    def dns_summary(self):
        proc = subprocess.Popen([self.tshark_path, '-r', self.out_pcap, '-R', "dns.qry.name"], stdout = subprocess.PIPE)
        dns_queries = proc.communicate()[0]
        return dns_queries

    def tcp_conv(self):
        proc = subprocess.Popen([self.tshark_path,'-z', 'conv,tcp', '-r', self.out_pcap, '-q', '-n'], stdout = subprocess.PIPE)
        tcp_conversations = proc.communicate()[0]
        return tcp_conversations

    def http_requests(self):
        proc = subprocess.Popen([self.tshark_path, '-r', self.out_pcap, '-R', "http.request", '-Tfields', '-e','ip.src', '-e', 'ip.dst', '-e', 'http.host'], stdout = subprocess.PIPE)
        http_requests = proc.communicate()[0]
        return http_requests

    def httpreq_tree(self):
        proc = subprocess.Popen(['tshark', '-z', 'http_req,tree', '-r', self.out_pcap, '-q', '-n'], stdout = subprocess.PIPE)
        http_request_tree = proc.communicate()[0]
        return http_request_tree
########################################[end of tshark class]######################################

########################################[tcpdump class]############################################
class Tcpdump:
    def __init__(self, tcpdump_path, out_pcap):

        if not os.path.isfile(tcpdump_path):
            print "cannot find tcpdump in %s" % tcpdump_path
            print "Exiting the program"
            sys.exit()

        self.tcpdump_path = tcpdump_path
        self.out_pcap = out_pcap
        self.proc = None

    def start_tcpdump(self, iface, ip):
        self.proc = subprocess.Popen([self.tcpdump_path, '-n', '-i', iface, 'host %s' % ip,  '-w', self.out_pcap])

    def stop_tcpdump(self):
        if self.proc != None:
            self.proc.terminate()

    def dns_summary(self):
        proc = subprocess.Popen([self.tcpdump_path, '-n', '-r', self.out_pcap, "udp and port 53"], stdout=subprocess.PIPE)
        dns_queries = proc.communicate()[0]
        return dns_queries

    def tcp_conv(self):
        proc = subprocess.Popen([self.tcpdump_path,'-n', '-q', '-r', self.out_pcap, "tcp"], stdout=subprocess.PIPE)
        tcp_conversations = proc.communicate()[0]
        return tcp_conversations


########################################[end of tcpdump class]######################################


########################################[fileregmon class]##########################################


class Fileregmon:

    def __init__(self, host_vmrun_path, host_vmtype, vmpath, username, password):
        self.host_vmrun_path = host_vmrun_path
        self.host_vmtype = host_vmtype
        self.vmpath = vmpath
        self.username = username
        self.password = password
        self.file_path = ""

    def get_filereg_activity(self, outfile_path):
        results = open(outfile_path).read()
        return results
#############################################[end of fileregmon class]############################


########################################[iptables class]##########################################

class Iptables:

    def __init__(self, iface):
        self.iface = iface

    def add_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-A", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])

    def delete_ip_port_redirect_entries(self):
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "8", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "10:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "20:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "54:68", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "70:122", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "124:513", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "515:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "9", "-j", "REDIRECT", "--to-port", "9"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "69", "-j", "REDIRECT", "--to-port", "69"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "123", "-j", "REDIRECT", "--to-port", "123"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "udp", "--dport", "514", "-j", "REDIRECT", "--to-port", "514"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "2:6", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "8:12", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "14:16", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "18", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "20", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "22:24", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "26:36", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "38:52", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "54:78", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "81:109", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "111:112", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "114:442", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "444:464", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "466:989", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "991:994", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "996:6666", "-j", "REDIRECT", "--to-port", "1"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6668:65535", "-j", "REDIRECT", "--to-port", "1"])

        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "7", "-j", "REDIRECT", "--to-port", "7"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "13", "-j", "REDIRECT", "--to-port", "13"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "17", "-j", "REDIRECT", "--to-port", "17"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "19", "-j", "REDIRECT", "--to-port", "19"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "21", "-j", "REDIRECT", "--to-port", "21"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "25", "-j", "REDIRECT", "--to-port", "25"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "37", "-j", "REDIRECT", "--to-port", "37"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "79", "-j", "REDIRECT", "--to-port", "79"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "80"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "110", "-j", "REDIRECT", "--to-port", "110"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "113", "-j", "REDIRECT", "--to-port", "113"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "443"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "465", "-j", "REDIRECT", "--to-port", "465"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "990", "-j", "REDIRECT", "--to-port", "990"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "995", "-j", "REDIRECT", "--to-port", "995"])
        subprocess.check_call(["iptables", "-D", "PREROUTING", "-t", "nat", "-i", self.iface, "-p", "tcp", "--dport", "6667", "-j", "REDIRECT", "--to-port", "6667"])


    def display_ip_port_redirect_entries(self):
        output = subprocess.check_output(["iptables", "-L", "-t" "nat"])
        print output


#############################################[end of fileregmon class]############################