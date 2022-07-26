import os.path
import socket
import subprocess
import sys
import time
import traceback
import signal

from scapy.all import raw, struct
from scapy.fields import BitField, StrLenField
from scapy.packet import Packet

RUSHB_PROTOCOL_VERSION = "0.1"

LOCAL_HOST = "127.0.0.1"
RECV_SIZE = 4096
TIME_OUT = 10

DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACKNOWLEDGE = 0x04
DATA = 0x05
QUERY = 0x06
AVAILABLE = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00


def handler(signum, frame):
    raise TimeoutError()


class RUSH(Packet):
    name = "RUSH"
    fields_desc = [
        BitField("source_ip", 0, 32),
        BitField("destination_ip", 0, 32),
        BitField("offset", 0, 24),
        BitField("mode", 0, 8),
    ]


class RUSHIp(RUSH):
    name = "RUSH_IP"
    fields_desc = [
        BitField("ip", 0, 32),
    ]


class RUSHData(RUSH):
    name = "RUSH_DATA"
    fields_desc = [
        StrLenField("data", "", length_from=lambda x: x.length),
    ]


class RUSHLocation(RUSH):
    name = "RUSH_LOCATION"
    fields_desc = [
        BitField("x", 0, 16),
        BitField("y", 0, 16),
    ]


class RUSHDistance(RUSH):
    name = "RUSH_DISTANCE"
    fields_desc = [
        BitField("target_ip", 0, 32),
        BitField("distance", 0, 32),
    ]


def str_to_int(string):
    b_str = string.encode("UTF-8")
    return int.from_bytes(b_str, byteorder='big')


def int_to_str(integer, size=11):
    return integer.to_bytes(size, byteorder='big').decode("UTF-8")


def ip_to_int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def build_packet(source_ip, destination_ip, offset, mode, misc=None):
    s_ip = ip_to_int(source_ip)
    d_ip = ip_to_int(destination_ip)
    try:
        pkt = RUSH(source_ip=s_ip, destination_ip=d_ip, offset=offset,
                   mode=mode)
        if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            t_ip = ip_to_int(misc)
            additional = RUSHIp(ip=t_ip)
        elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            additional = misc.encode('utf-8')
        elif mode == LOCATION:
            additional = RUSHLocation(x=misc[0], y=misc[1])
        elif mode is DISTANCE:
            t_ip = ip_to_int(misc[0])
            additional = RUSHDistance(target_ip=t_ip, distance=misc[1])
        else:
            additional = None
    except:
        traceback.print_exc(file=sys.stderr)
        assert False, f"There is a problem while building packet."
    return pkt, additional


def int_to_location(data):
    x = data & 0x11110000 >> 8
    y = data & 0x00001111
    return f'x = {x}, y = {y}'


def new_tcp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((LOCAL_HOST, port))
    return sock


def new_udp_socket(port) -> socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LOCAL_HOST, port))
    return sock


class Connection:
    def __init__(self, output, path="./", error=sys.stderr):
        self._proc = []
        self._my_sockets = []
        self._target_sockets = []
        self._path = path
        self._output = output
        self._error = error

    def _send(self, pkt, additional, sock, target_info=None, print_out=False,
              extend_message=""):
        time.sleep(0.2)
        try:
            message = raw(pkt)
            if additional is not None:
                message += raw(additional)
            if target_info is None:
                sock.sendall(message)
            else:
                sock.sendto(message, target_info)
            if print_out:
                self._print(pkt, additional, f"{extend_message}Sent: ")
        except:
            traceback.print_exc(file=self._error)
            assert False, f"Error while sending a message to a socket."

    def _recv(self, sock, size=RECV_SIZE, print_out=False, extend_message=""):
        try:
            raw_data, info = sock.recvfrom(size)
        except:
            traceback.print_exc(file=self._error)
            assert False, f"Error while receiving a message from a socket."
        try:
            mode = raw_data[11]
            pkt = RUSH(raw_data[:12])
            left_over = raw_data[12:]
            if mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
                additional = RUSHIp(left_over[:4])
            elif mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
                additional = left_over[:1488]
            elif mode == LOCATION:
                additional = RUSHLocation(left_over[:4])
            elif mode is DISTANCE:
                additional = RUSHDistance(left_over[:8])
            else:
                additional = ""
            if print_out:
                self._print(pkt, additional, f"{extend_message}Received: ")
            return pkt, additional, info
        except:
            traceback.print_exc(file=self._error)
            assert False, "Could not decode packet: " + repr(raw_data)

    def _print(self, pkt, additional, init=""):
        if pkt.mode in (DISCOVERY, OFFER, REQUEST, ACKNOWLEDGE):
            misc = f"assigned_ip={int_to_ip(additional.ip)}"
        elif pkt.mode in (DATA, MORE_FRAG, END_FRAG, INVALID):
            misc = f"data={additional.decode('utf-8')}"
        elif pkt.mode is LOCATION:
            misc = f"x={additional.x}, y={additional.y}"
        elif pkt.mode is DISTANCE:
            misc = f"target_ip={int_to_ip(additional.target_ip)}, distance={additional.distance}"
        else:
            misc = "no_extra_data"
        output = f"{init}(source_ip={int_to_ip(pkt.source_ip)}, destination_ip={int_to_ip(pkt.destination_ip)}, " \
                 f"offset={pkt.offset}, mode={pkt.mode}, {misc})"
        self._output.write(output + "\n")
        self._output.flush()

    def close(self):
        for sock in self._target_sockets:
            sock.close()
        for sock in self._target_sockets:
            sock.close()

    def _assert(self, condition, message):
        if not condition:
            self.tear_down()
        assert condition, message

    def tear_down(self):
        for i in self._proc:
            if i is not None:
                i.kill()
        self.close()

    def _start_adapter(self, port, sin=subprocess.PIPE, sout=subprocess.PIPE, serr=subprocess.PIPE):
        if os.path.isfile(self._path + "RUSHBAdapter.py"):
            self._proc.append(subprocess.Popen(["python3", "RUSHBAdapter.py", port], stdin=sin, stdout=sout, stderr=serr,cwd=self._path))
        elif os.path.isfile(self._path + "RUSHBAdapter.class"):
            if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                self._proc.append(subprocess.Popen(["java", "RUSHBAdapter", port], stdin=sin, stdout=sout, stderr=serr,cwd=self._path))
            else:
                self._assert(False, "[Adapter] There is a java class file but no makefile")
        elif os.path.isfile(self._path + "RUSHBAdapter"):
            if os.path.isfile(self._path + "makefile") or os.path.isfile(
                    self._path + "Makefile"):
                self._proc.append(subprocess.Popen(["./RUSHBAdapter", port],stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
            else:
                self._assert(False, "[Adapter] There is an executable file but no makefile")
        else:
            self._assert(False, "[Adapter] Could not find assignment file")
        return self._proc[-1]

    def _start_switch(self, mode, ip1, x, y, ip2=None, sin=subprocess.PIPE, sout=subprocess.PIPE, serr=subprocess.PIPE):
        if ip2 is not None:
            if os.path.isfile(self._path + "RUSHBSwitch.py"):
                self._proc.append(subprocess.Popen(["python3", "RUSHBSwitch.py", mode, ip1, ip2, x, y], stdin=sin, stdout=sout, stderr=serr, cwd=self._path))
            elif os.path.isfile(self._path + "RUSHBSwitch.class"):
                if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                    self._proc.append(subprocess.Popen(["java", "RUSHBSwitch", mode, ip1, ip2, x, y], stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
                else:
                    self._assert(False, "[Switch] There is a java class file but no makefile")
            elif os.path.isfile(self._path + "RUSHBSwitch"):
                if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                    self._proc.append(
                        subprocess.Popen(["./RUSHBSwitch", mode, ip1, ip2, x, y], stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
                else:
                    self._assert(False, "[Switch] There is an executable file but no makefile")
            else:
                self._assert(False, "[Switch] Could not find assignment file")
        else:
            if os.path.isfile(self._path + "RUSHBSwitch.py"):
                self._proc.append(subprocess.Popen(["python3", "RUSHBSwitch.py", mode, ip1, x, y], stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
            elif os.path.isfile(self._path + "RUSHBSwitch.class"):
                if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                    self._proc.append(subprocess.Popen(["java", "RUSHBSwitch", mode, ip1, x, y], stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
                else:
                    self._assert(False, "[Switch] There is a java class file but no makefile")
            elif os.path.isfile(self._path + "RUSHBSwitch"):
                if os.path.isfile(self._path + "makefile") or os.path.isfile(self._path + "Makefile"):
                    self._proc.append(subprocess.Popen(["./RUSHBSwitch", mode, ip1, x, y], stdin=sin, stdout=sout,stderr=serr, cwd=self._path))
                else:
                    self._assert(False, "[Switch] There is an executable file but no makefile")
            else:
                self._assert(False, "[Switch] Could not find assignment file")
        return self._proc[-1]

    def check_output(self, f1="", f2="", id_test=0, test_name="", max_mark=0):
        self._error.write(f"Done, now comparing output...\n")
        self._error.flush()
        result = "OK"
        err = ""
        try:
            with open(f1, "r") as f, open(f2, "r") as g:
                output = g.readlines()
                expected = f.readlines()
                if len(expected) != len(output):
                    self._assert(False, f'\tNumber of lines mismatch')
                for i in range(len(expected)):
                    if expected[i].strip() != output[i].strip():
                        self._assert(False, f'\tMissing {expected[i]}')
        except AssertionError as e:
            err = e.args[0] + '\n'
            result = "FAIL"
        except:
            if "EXEC" not in test_name and "GET_PORT" not in test_name:
                result = "ERROR"
        sys.stdout.write(f'Test {id_test:02} - {test_name:30} :{result:10}')
        mark = 0
        if result == "OK":
            mark = max_mark
        sys.stdout.write(f"{mark:>5}/{max_mark}\n" + err)
        sys.stdout.flush()
        return mark

    def adapter_exec(self):
        self._error.write("---- TEST 0: ADAPTER_EXEC\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        self._start_adapter(port)

    def adapter_get_port(self):
        self._error.write("---- TEST 1: ADAPTER_GET_PORT\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        self._start_adapter(port)
        msg, info = sock.recvfrom(16)
        self.tear_down()

    def adapter_greeting(self):
        self._error.write("---- TEST 2: ADAPTER_GREETING\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(
            f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        self._start_adapter(port)
        data, add, info = self._recv(sock, size=16, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True, size=16)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=ACKNOWLEDGE, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self.tear_down()

    def adapter_receiving(self):
        self._error.write("---- TEST 3+4: ADAPTER_RECEIVING\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        proc = self._start_adapter(port)
        data, add, info = self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=ACKNOWLEDGE, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="130.102.71.65", destination_ip="192.168.1.2", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        with open("ADAPTER_RECEIVING_2.tout", "w") as f:
            data = proc.stdout.read(47)
            f.write(data.decode("utf-8"))
        self.tear_down()

    def adapter_sending(self):
        self._error.write("---- TEST 5: ADAPTER_SENDING\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        flags = os.O_RDWR
        fd = os.open("test_files/ADAPTER_SENDING.in", flags)
        self._start_adapter(port, sin=fd)
        data, add, info = self._recv(sock, size=16, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True, size=16)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=ACKNOWLEDGE, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        os.close(fd)
        self.tear_down()

    def adapter_fragmentation(self):
        self._error.write("---- TEST 6+7: ADAPTER_FRAGMENTATION\n")
        self._error.flush()
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        port = str(sock.getsockname()[1])
        self._error.write(f"New UDP port opened at {port}. Now executing adapter...\n")
        self._error.flush()
        proc = self._start_adapter(port)
        data, add, info = self._recv(sock, size=16, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True, size=16)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=ACKNOWLEDGE, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000000, mode=MORE_FRAG, misc="a" * 1488)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x0005d0, mode=MORE_FRAG, misc="b" * 1488)
        self._send(pkt, add, sock, target_info=info, print_out=True)
        pkt, add = build_packet(source_ip="192.168.1.1", destination_ip="192.168.1.2", offset=0x000ba0, mode=END_FRAG, misc="c")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        with open("ADAPTER_FRAGMENTATION_2.tout", "w") as f:
            data = proc.stdout.readline()
            f.write(data.decode("UTF-8"))
        self.tear_down()

    def switch_exec_1(self):
        self._error.write("---- TEST 0: SWITCH_EXEC_1\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        self._start_switch("local", "192.168.1.1/24", "0", "2")
        self.tear_down()

    def switch_exec_2(self):
        self._error.write("---- TEST 1: SWITCH_EXEC_2\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        self._start_switch("local", "192.168.1.1/24", "0", "2", "130.0.0.1/8")
        self.tear_down()

    def switch_exec_3(self):
        self._error.write("---- TEST 2: SWITCH_EXEC_3\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        self._start_switch("global", "130.0.0.1/8", "0", "2")
        self.tear_down()

    def switch_get_port_1(self):
        self._error.write("---- TEST 3: SWITCH_GET_PORT_1\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
        self.tear_down()

    def switch_get_port_2(self):
        self._error.write("---- TEST 4: SWITCH_GET_PORT_2\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        proc = self._start_switch("global", "130.0.0.1/8", "0", "2")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number:")
        self.tear_down()

    def switch_get_port_3(self):
        self._error.write("---- TEST 5: SWITCH_GET_PORT_3\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", "130.0.0.1/8")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
        self.tear_down()

    def switch_greeting_adapter(self):
        self._error.write("---- TEST 6: SWITCH_GREETING_ADAPTER\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)
        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        self.tear_down()

    def switch_multi_adapter(self):
        self._error.write("---- TEST 7: SWITCH_MULTI_ADAPTER\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()

        proc = self._start_switch("local", "192.168.1.1/24", "0", "2")
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)

        sock = new_udp_socket(0)
        self._my_sockets.append(sock)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.3")
        self._send(pkt, add, sock, target_info=info, print_out=True)
        self._recv(sock, print_out=True)

        self.tear_down()

    def _switch_offer(self, sock, target, host_ip, assigned_ip, location=(0, 0), switch_name="[S] "):
        try:
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip="0.0.0.0", offset=0x000000, mode=OFFER, misc=assigned_ip)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip=assigned_ip, offset=0x000000, mode=ACKNOWLEDGE, misc=assigned_ip)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
            self._recv(sock, print_out=True, extend_message=switch_name)
            pkt, add = build_packet(source_ip=host_ip, destination_ip=assigned_ip, offset=0x000000, mode=LOCATION, misc=location)
            self._send(pkt, add, sock, target_info=target, print_out=True, extend_message=switch_name)
        except:
            assert False, f"Error while receiving a message from a socket in switch offer."

    def switch_global_greeting(self):
        self._error.write("---- TEST 8: SWITCH_GLOBAL_GREETING\n")
        self._error.flush()

        # sock 2 listens from target
        tcp_sock_2 = new_tcp_socket(0)
        self._my_sockets.append(tcp_sock_2)

        port = str(tcp_sock_2.getsockname()[1])
        with open(f"SWITCH_GLOBAL_GREETING.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port)}\n")
            port_writer.flush()
        flags = os.O_RDWR
        fd = os.open("SWITCH_GLOBAL_GREETING.in", flags)
        proc = self._start_switch("global", "130.0.0.1/8", "2", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        # [S2] listen from [T]
        tcp_sock_2.listen()
        conn, addr = tcp_sock_2.accept()
        self._target_sockets.append(conn)
        switch_name_2 = ""
        self._switch_offer(conn, addr, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 2), switch_name=switch_name_2)

        os.close(fd)
        self.tear_down()

    def minimap_3(self):
        self._error.write("---- TEST 9: MINIMAP_3\n")
        self._error.flush()

        tcp_sock_1 = new_tcp_socket(0)  # sock 1
        tcp_sock_2 = new_tcp_socket(0)  # sock 2
        self._my_sockets.append(tcp_sock_1)
        self._my_sockets.append(tcp_sock_2)

        port = str(tcp_sock_2.getsockname()[1])
        with open(f"SWITCH_GLOBAL_GREETING.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port)}\n")
            port_writer.flush()
        flags = os.O_RDWR
        fd = os.open("SWITCH_GLOBAL_GREETING.in", flags)
        proc = self._start_switch("global", "130.0.0.1/8", "2", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()

        info = (LOCAL_HOST, port)

        # [S1] connect to [T]
        switch_name_1 = "[S1] "
        tcp_sock_1.connect(info)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="130.0.0.1", offset=0x000000, mode=REQUEST, misc="130.0.0.2")
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)
        pkt, add = build_packet(source_ip="130.0.0.2", destination_ip="130.0.0.1", offset=0x000000, mode=LOCATION, misc=(2, 0))
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)

        # [S2] listen from [T]
        tcp_sock_2.listen()
        conn, addr = tcp_sock_2.accept()
        self._target_sockets.append(conn)
        switch_name_2 = "[S2] "
        self._switch_offer(conn, addr, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 2), switch_name=switch_name_2)

        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)

        tcp_sock_2 = conn

        # [S2] forwards the distance of local network to [T]
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=DISTANCE, misc=("10.0.0.1", 10))
        self._send(pkt, add, tcp_sock_2, target_info=info, print_out=True, extend_message=switch_name_2)
        # [S1] receives the location from [T]
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)
        # [S1] sends the data to destination
        pkt, add = build_packet(source_ip="130.0.0.2", destination_ip="130.0.0.1", offset=0x000000, mode=QUERY)
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="10.0.0.6", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        # [S2] now receives message from [T]
        self._recv(tcp_sock_2, print_out=True, extend_message=switch_name_2)
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, tcp_sock_2, target_info=info, print_out=True, extend_message=switch_name_2)
        self._recv(tcp_sock_2, print_out=True, extend_message=switch_name_2)
        # [S2] wait 5 seconds to let [T] establishes the query to [S1]
        time.sleep(5)
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=QUERY)
        self._send(pkt, add, tcp_sock_2, target_info=info, print_out=True, extend_message=switch_name_2)
        self._recv(tcp_sock_2, print_out=True, extend_message=switch_name_2)
        # [S2] sends message back to [T] and [T] has to remember the path
        pkt, add = build_packet(source_ip="10.0.0.6", destination_ip="192.168.1.2", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, tcp_sock_2, target_info=info, print_out=True, extend_message=switch_name_2)
        # [S1] now receive the query and the message
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)
        pkt, add = build_packet(source_ip="130.0.0.2", destination_ip="130.0.0.1", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, tcp_sock_1, target_info=info, print_out=True, extend_message=switch_name_1)
        self._recv(tcp_sock_1, print_out=True, extend_message=switch_name_1)

        self.tear_down()
        os.close(fd)

    def switch_local2_greeting(self):
        self._error.write("---- TEST 10: SWITCH_LOCAL2_GREETING\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()

        proc = self._start_switch("local", "10.0.0.1/8", "2", "2", "130.0.0.1/8")
        try:
            next_line = proc.stdout.readline()
            local_port = int(next_line.decode("utf-8").rstrip())
            next_line = proc.stdout.readline()
            global_port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {local_port} and {global_port}\n")
        self._error.flush()
        udp_info = (LOCAL_HOST, local_port)
        tcp_info = (LOCAL_HOST, global_port)

        # [A] greeting with [T]
        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=udp_info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="10.0.0.1", offset=0x000000, mode=REQUEST, misc="10.0.0.2")
        self._send(pkt, add, udp_sock, target_info=udp_info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)

        # [S] greeting with [T]
        tcp_sock = new_tcp_socket(0)
        self._my_sockets.append(tcp_sock)
        switch_name = "[S] "
        tcp_sock.connect(tcp_info)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, tcp_sock, target_info=tcp_info, print_out=True, extend_message=switch_name)
        self._recv(tcp_sock, print_out=True, extend_message=switch_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="130.0.0.1", offset=0x000000, mode=REQUEST, misc="130.0.0.2")
        self._send(pkt, add, tcp_sock, target_info=tcp_info, print_out=True, extend_message=switch_name)
        self._recv(tcp_sock, print_out=True, extend_message=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.2", destination_ip="130.0.0.1", offset=0x000000, mode=LOCATION, misc=(2, 0))
        self._send(pkt, add, tcp_sock, target_info=tcp_info, print_out=True, extend_message=switch_name)
        self._recv(tcp_sock, print_out=True, extend_message=switch_name, size=16)  # location
        # checking method has removed in student mode test suite
        self._recv(tcp_sock, print_out=True, extend_message=switch_name, size=20)  # distance
        self.tear_down()

    def switch_forward_message(self):
        self._error.write("---- TEST 11: SWITCH_FORWARD_ADAPTER\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()

        tcp_sock = new_tcp_socket(0)  # tcp connection
        self._my_sockets.append(tcp_sock)
        port = str(tcp_sock.getsockname()[1])
        with open("./SWITCH_FORWARD_MESSAGE.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port)}\n")
            port_writer.flush()

        flags = os.O_RDWR
        fd = os.open("SWITCH_FORWARD_MESSAGE.in", flags)
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        tcp_sock.listen()
        conn, addr = tcp_sock.accept()
        self._target_sockets.append(conn)
        switch_name = "[S] "
        self._switch_offer(conn, addr, host_ip="130.0.0.1", assigned_ip="130.0.0.2", switch_name=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=DISTANCE, misc=("20.0.0.1", 10))
        self._send(pkt, add, conn, target_info=addr, print_out=True, extend_message=switch_name)

        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="135.0.0.1", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)

        # tcp connection
        self._recv(conn, print_out=True, extend_message=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, conn, target_info=info, print_out=True, extend_message=switch_name)
        self._recv(conn, print_out=True, extend_message=switch_name)

        os.close(fd)
        self.tear_down()

    def switch_distance_switch(self):
        self._error.write("---- TEST 12: SWITCH_DISTANCE_SWITCH\n")
        self._error.flush()
        tcp_sock_1 = new_tcp_socket(0)  # sock 1
        self._my_sockets.append(tcp_sock_1)
        port_1 = str(tcp_sock_1.getsockname()[1])
        tcp_sock_1.listen()

        tcp_sock_2 = new_tcp_socket(0)  # sock 2
        self._my_sockets.append(tcp_sock_2)
        port_2 = str(tcp_sock_2.getsockname()[1])
        tcp_sock_2.listen()

        with open(f"SWITCH_DISTANCE_SWITCH.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port_1)}\nconnect {str(port_2)}\n")
            port_writer.flush()

        flags = os.O_RDWR
        fd = os.open("SWITCH_DISTANCE_SWITCH.in", flags)
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        # info = (LOCAL_HOST, port)

        conn_1, addr_1 = tcp_sock_1.accept()
        self._target_sockets.append(conn_1)
        switch_1_name = "[S1] "
        self._switch_offer(conn_1, addr_1, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 0), switch_name=switch_1_name)

        conn_2, addr_2 = tcp_sock_2.accept()
        self._target_sockets.append(conn_2)
        switch_2_name = "[S2] "
        self._switch_offer(conn_2, addr_2, host_ip="136.0.0.1", assigned_ip="136.0.0.2", location=(0, 4), switch_name=switch_2_name)
        self._recv(conn_1, print_out=True, extend_message=switch_1_name)

        self.tear_down()

    def switch_routing_simple(self):
        self._error.write("---- TEST 13: SWITCH_ROUTING_SIMPLE\n")
        self._error.flush()
        tcp_sock_1 = new_tcp_socket(0)  # sock 1
        self._my_sockets.append(tcp_sock_1)
        port_1 = str(tcp_sock_1.getsockname()[1])
        tcp_sock_1.listen()

        tcp_sock_2 = new_tcp_socket(0)  # sock 2
        self._my_sockets.append(tcp_sock_2)
        port_2 = str(tcp_sock_2.getsockname()[1])
        tcp_sock_2.listen()

        with open(f"SWITCH_ROUTING_SIMPLE.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port_1)}\nconnect {str(port_2)}\n")
            port_writer.flush()

        flags = os.O_RDWR
        fd = os.open("SWITCH_ROUTING_SIMPLE.in", flags)
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        conn_1, addr_1 = tcp_sock_1.accept()
        self._target_sockets.append(conn_1)
        switch_1_name = "[S1] "
        self._switch_offer(conn_1, addr_1, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 0), switch_name=switch_1_name)

        conn_2, addr_2 = tcp_sock_2.accept()
        self._target_sockets.append(conn_2)
        switch_2_name = "[S2] "
        self._switch_offer(conn_2, addr_2, host_ip="136.0.0.1", assigned_ip="136.0.0.2", location=(0, 4), switch_name=switch_2_name)
        self._recv(conn_1, print_out=True, extend_message=switch_1_name)

        info_1 = (conn_1, addr_1)
        info_2 = (conn_2, addr_2)

        # [S1] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", 3))
        self._send(pkt, add, info_1[0], target_info=info_1[1], print_out=True, extend_message=switch_1_name)
        # [T] -> [S2] : D([S3])
        self._recv(info_2[0], print_out=True, extend_message=switch_2_name)
        # [S2] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="136.0.0.1", destination_ip="136.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", 5))
        self._send(pkt, add, info_2[0], target_info=info_2[1], print_out=True, extend_message=switch_2_name)
        # [T] -> [S1] : D([S3])
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        # [A] -> [T] : "HELLO WORLD"

        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="134.0.0.1", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        # [T] -> [S1]
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, info_1[0], target_info=info, print_out=True, extend_message=switch_1_name)
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)

        self.tear_down()

    def switch_routing_prefix(self):
        self._error.write("---- TEST 14: SWITCH_ROUTING_PREFIX\n")
        self._error.flush()
        tcp_sock_1 = new_tcp_socket(0)  # sock 1
        self._my_sockets.append(tcp_sock_1)
        port_1 = str(tcp_sock_1.getsockname()[1])
        tcp_sock_1.listen()

        tcp_sock_2 = new_tcp_socket(0)  # sock 2
        self._my_sockets.append(tcp_sock_2)
        port_2 = str(tcp_sock_2.getsockname()[1])
        tcp_sock_2.listen()

        with open(f"SWITCH_ROUTING_PREFIX.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port_1)}\nconnect {str(port_2)}\n")
            port_writer.flush()

        flags = os.O_RDWR
        fd = os.open("SWITCH_ROUTING_PREFIX.in", flags)
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        conn_1, addr_1 = tcp_sock_1.accept()
        self._target_sockets.append(conn_1)
        switch_1_name = "[S1] "
        self._switch_offer(conn_1, addr_1, host_ip="135.0.0.1", assigned_ip="135.0.0.2", location=(0, 0), switch_name=switch_1_name)

        conn_2, addr_2 = tcp_sock_2.accept()
        self._target_sockets.append(conn_2)
        switch_2_name = "[S2] "
        self._switch_offer(conn_2, addr_2, host_ip="136.0.0.1", assigned_ip="136.0.0.2", location=(0, 4), switch_name=switch_2_name)
        self._recv(conn_1, print_out=True, extend_message=switch_1_name)

        info_1 = (conn_1, addr_1)
        info_2 = (conn_2, addr_2)

        # [S1] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", 5))
        self._send(pkt, add, info_1[0], target_info=info_1[1], print_out=True, extend_message=switch_1_name)
        # [T] -> [S2] : D([S3])
        self._recv(info_2[0], print_out=True, extend_message=switch_2_name)
        # [S2] -> [T] : D([S3])
        pkt, add = build_packet(source_ip="136.0.0.1", destination_ip="136.0.0.2", offset=0x000000, mode=DISTANCE, misc=("134.0.0.1", 3))
        self._send(pkt, add, info_2[0], target_info=info_2[1], print_out=True, extend_message=switch_2_name)
        # [T] -> [S1] : D([S3])
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        # [A] -> [T] : "HELLO WORLD"

        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="129.0.0.1", offset=0x000000, mode=DATA, misc="HELLO WORLD")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        # [T] -> [S1]
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)
        pkt, add = build_packet(source_ip="135.0.0.1", destination_ip="135.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, info_1[0], target_info=info, print_out=True, extend_message=switch_1_name)
        self._recv(info_1[0], print_out=True, extend_message=switch_1_name)

        self.tear_down()

    def switch_fragmentation(self):
        self._error.write("---- TEST 15: SWITCH_FRAGMENTATION\n")
        self._error.flush()
        self._error.write("Calling the switch now to get the port number...\n")
        self._error.flush()

        tcp_sock = new_tcp_socket(0)  # tcp connection
        self._my_sockets.append(tcp_sock)
        port = str(tcp_sock.getsockname()[1])
        with open("./SWITCH_FRAGMENTATION.in", "w+") as port_writer:
            port_writer.write(f"connect {str(port)}\n")
            port_writer.flush()

        flags = os.O_RDWR
        fd = os.open("SWITCH_FRAGMENTATION.in", flags)
        proc = self._start_switch("local", "192.168.1.1/24", "0", "2", sin=fd)
        try:
            next_line = proc.stdout.readline()
            port = int(next_line.decode("utf-8").rstrip())
        except:
            self._assert(False, f"Couldn't decode port number")
            return
        self._error.write(f"Received the switch's port number: {port}\n")
        self._error.flush()
        info = (LOCAL_HOST, port)

        tcp_sock.listen()
        conn, addr = tcp_sock.accept()
        self._target_sockets.append(conn)
        switch_name = "[S] "
        self._switch_offer(conn, addr, host_ip="130.0.0.1", assigned_ip="130.0.0.2", switch_name=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=DISTANCE, misc=("20.0.0.1", 10))
        self._send(pkt, add, conn, target_info=addr, print_out=True, extend_message=switch_name)

        udp_sock = new_udp_socket(0)  # udp connection
        self._my_sockets.append(udp_sock)
        adapter_name = "[A] "
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="0.0.0.0", offset=0x000000, mode=DISCOVERY, misc="0.0.0.0")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        pkt, add = build_packet(source_ip="0.0.0.0", destination_ip="192.168.1.1", offset=0x000000, mode=REQUEST, misc="192.168.1.2")
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)
        self._recv(udp_sock, print_out=True, extend_message=adapter_name)
        payload = 'a' * 1500
        pkt, add = build_packet(source_ip="192.168.1.2", destination_ip="135.0.0.1", offset=0x000000, mode=DATA, misc=payload)
        self._send(pkt, add, udp_sock, target_info=info, print_out=True, extend_message=adapter_name)

        # tcp connection
        self._recv(conn, print_out=True, extend_message=switch_name)
        pkt, add = build_packet(source_ip="130.0.0.1", destination_ip="130.0.0.2", offset=0x000000, mode=AVAILABLE)
        self._send(pkt, add, conn, target_info=info, print_out=True, extend_message=switch_name)
        self._recv(conn, print_out=True, extend_message=switch_name, size=1500)
        self._recv(conn, print_out=True, extend_message=switch_name)

        os.close(fd)
        self.tear_down()


ADAPTER_EXEC = Connection.adapter_exec
ADAPTER_GET_PORT = Connection.adapter_get_port
ADAPTER_GREETING = Connection.adapter_greeting
ADAPTER_RECEIVING = Connection.adapter_receiving
ADAPTER_SENDING = Connection.adapter_sending
ADAPTER_FRAGMENTATION = Connection.adapter_fragmentation

SWITCH_EXEC_1 = Connection.switch_exec_1
SWITCH_EXEC_2 = Connection.switch_exec_2
SWITCH_EXEC_3 = Connection.switch_exec_3
SWITCH_GET_PORT_1 = Connection.switch_get_port_1
SWITCH_GET_PORT_2 = Connection.switch_get_port_2
SWITCH_GET_PORT_3 = Connection.switch_get_port_3
SWITCH_GREETING_ADAPTER = Connection.switch_greeting_adapter
SWITCH_MULTI_ADAPTER = Connection.switch_multi_adapter
SWITCH_GLOBAL_GREETING = Connection.switch_global_greeting
MINIMAP_3 = Connection.minimap_3
SWITCH_LOCAL2_GREETING = Connection.switch_local2_greeting
SWITCH_FORWARD_MESSAGE = Connection.switch_forward_message
SWITCH_DISTANCE_SWITCH = Connection.switch_distance_switch
SWITCH_ROUTING_SIMPLE = Connection.switch_routing_simple
SWITCH_ROUTING_PREFIX = Connection.switch_routing_prefix
SWITCH_FRAGMENTATION = Connection.switch_fragmentation


def check_and_build(base_folder):
    dic_cont = os.listdir(base_folder)
    if len(dic_cont) != 0:
        for item in dic_cont:
            if os.path.isdir(item) and item[0] != "." and item != "test_files" and item != "scapy":
                sys.stdout.write(f"Detected sub-directory: {item}\n")
                sys.stdout.flush()
    for item in dic_cont:
        if os.path.isfile(item) and item[-5:] == ".tout":
            os.remove(item)
    path = base_folder
    if os.path.isfile(path + "makefile") or os.path.isfile(path + "Makefile"):
        sys.stderr.write('Calling make...')
        sys.stderr.flush()
        try:
            subprocess.check_output(["make"], cwd=path)
        except subprocess.CalledProcessError:
            assert False, "Error occurred while calling make."


def main(argv):
    sys.stdout.write('RUSHB_MARKING_VERSION: ' + RUSHB_PROTOCOL_VERSION + '\n')
    sys.stdout.flush()

    dic_cont = os.listdir(".")
    for item in dic_cont:
        if os.path.isfile(item) and (item[-5:] == ".tout" or item[-3:] == ".in"):
            os.remove(item)

    if len(argv) > 2:
        print("Usage: python3 testa2c.py [path_to_RUSHB[Adapter|Switch]/]")
        return

    test_folder = argv[1] if len(argv) == 2 else "./"
    test_folder = test_folder if test_folder[-1] == "/" else test_folder + "/"

    try:
        check_and_build(test_folder)
    except AssertionError as e:
        sys.stdout.write(f"Makefile error at: {e.args[0]}.\n")
        sys.stdout.flush()
        return

    mode_list = (SWITCH_EXEC_1,
                 SWITCH_EXEC_2,
                 SWITCH_EXEC_3,
                 SWITCH_GET_PORT_1,
                 SWITCH_GET_PORT_2,
                 SWITCH_GET_PORT_3,
                 SWITCH_GREETING_ADAPTER,
                 SWITCH_MULTI_ADAPTER,
                 SWITCH_GLOBAL_GREETING,
                 MINIMAP_3,
                 SWITCH_LOCAL2_GREETING,
                 SWITCH_FORWARD_MESSAGE,
                 SWITCH_DISTANCE_SWITCH,
                 SWITCH_ROUTING_SIMPLE,
                 SWITCH_ROUTING_PREFIX,
                 SWITCH_FRAGMENTATION)

    mode_str = ("SWITCH_EXEC_1",
                "SWITCH_EXEC_2",
                "SWITCH_EXEC_3",
                "SWITCH_GET_PORT_1",
                "SWITCH_GET_PORT_2",
                "SWITCH_GET_PORT_3",
                "SWITCH_GREETING_ADAPTER",
                "SWITCH_MULTI_ADAPTER",
                "SWITCH_GLOBAL_GREETING",
                "MINIMAP_3",
                "SWITCH_LOCAL2_GREETING",
                "SWITCH_FORWARD_MESSAGE",
                "SWITCH_DISTANCE_SWITCH",
                "SWITCH_ROUTING_SIMPLE",
                "SWITCH_ROUTING_PREFIX",
                "SWITCH_FRAGMENTATION")
    mode_mark = (3, 3, 3, 3, 3, 3, 3, 3, 3, 5, 3, 3, 3, 3, 3, 3)

    sys.stdout.write(f"-------------------------------------------------------------\n")
    sys.stdout.flush()

    test_num = 0
    mark = 0

    for index, mode in enumerate(mode_list):
        try:
            out_file = f"{mode_str[index]}.tout"
            with open(out_file, "w") as f:

                signal.signal(signal.SIGALRM, handler)
                signal.alarm(TIME_OUT)

                conn = Connection(output=f, path=test_folder)
                mode(conn)
                mark += conn.check_output(f1=f"test_files/{mode_str[index]}.tout", f2=out_file, id_test=test_num, test_name=mode_str[index], max_mark=mode_mark[index])

                signal.alarm(0)
        except AssertionError as e:
            result = "ASSERT_ERR"
            sys.stdout.write(f'Test {test_num:02} - {mode_str[index]:30} :{result:10}')
            sys.stderr.write(e.args[0] + "\n")
            sys.stdout.write(f"{0:>5}/{mode_mark[index]}\n")
            sys.stderr.flush()
            sys.stdout.flush()
            conn.tear_down()
        except TimeoutError:
            result = "TIMEOUT"
            sys.stdout.write(f'Test {test_num:02} - {mode_str[index]:30} :{result:10}')
            sys.stdout.write(f"{0:>5}/{mode_mark[index]}\n")
            sys.stdout.flush()
            conn.tear_down()
        except:
            result = "OTHER_ERR"
            sys.stdout.write(f'Test {test_num:02} - {mode_str[index]:30} :{result:10}')
            sys.stdout.write(f"{0:>5}/{mode_mark[index]}\n")
            sys.stdout.flush()
            conn.tear_down()
        test_num += 1

    sys.stdout.write(f"-------------------------------------------------------------\n")
    sys.stdout.write(f"TOTAL: {mark:50}/{sum(mode_mark)}\n")
    sys.stdout.flush()
    sys.exit(mark)


if __name__ == "__main__":
    main(sys.argv)
