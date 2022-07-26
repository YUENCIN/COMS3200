"""
Sample RUSHBAdapter with no styles, but contains hints for RUSHBSwitch
It's better to read comments in the file
"""

import sys, socket, ipaddress, time, threading

LOCAL_HOST = "127.0.0.1"
BUFFER_SIZE = 1024
RESERVED_BITS = 0
PACKET_SIZE = 1500

# Modes
DISCOVERY_01 = 0x01
OFFER_02 = 0x02
REQUEST_03 = 0x03
ACK_04 = 0x04
ASK_06 = 0x06
DATA_05 = 0x05
READY_07 = 0x07
LOCATION_08 = 0x08
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b

class Connection():
    '''
    Connection to a single switch
    '''
    def __init__(self, ip, port_num):
        self.ip = ip
        self.port_num = port_num
        self._recv_packets = []

    def __eq__(self, other):
        if not isinstance(other, Connection):
            return False 
        return self.ip == other.ip and self.port_num == other.port_num



class Adapter():
    def __init__(self):
        self.switch_num = int(sys.argv[1])
        self.adapter = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.send_packets = []
        self.recv_packets = []
        self.ip = None # should contain 4 numbers
        self.switch_ips = []
        self.message = ''
        self.within_5_sec = 0
        self.connections = []
        self.ready = False
        self.lock = threading.Lock()
        self.ack = False
        self.switch_message = dict() # key: source_ip, value = [message]


    def create_packet(self, mode, source_ip='0.0.0.0', dest_ip='0.0.0.0', data='0.0.0.0'):
        packet = bytearray()

        # append source ip
        for elem in socket.inet_aton(source_ip):
            packet.append(elem)

        # append dest ip
        for elem in socket.inet_aton(dest_ip):
            packet.append(elem)

        # append reserve
        for _ in range(3):
            packet.append(RESERVED_BITS)
        
        # append mode
        packet.append(mode)

        try:
            socket.inet_aton(data)
        except socket.error:
            for char in data:
                packet.append(ord(char))
        else:
            # append assigned address
            for elem in socket.inet_aton(data):
                packet.append(elem)

        self.send_packets.append(packet)
        return packet

    def greeting(self):
        # send discovery
        discovery_packet = self.create_packet(DISCOVERY_01)
        send_address = (LOCAL_HOST, self.switch_num)
        self.adapter.sendto(discovery_packet, send_address)

        # receive offer
        offer = self.adapter.recvfrom(PACKET_SIZE)
        offerMessage = offer[0]
        # offerMessage = offer[0].decode().rstrip('\x00')
        self.recv_packets.append(offerMessage)
        # Check offer mode
        # Get switch ip and assigned ip
        switch_ip = ipaddress.IPv4Address(offerMessage[:4]) 

        self.switch_ips.append(switch_ip)

        self.ip = ipaddress.IPv4Address(int.from_bytes(offerMessage[12:16], byteorder='big'))

        # send request
        request_packet = self.create_packet(REQUEST_03, dest_ip=str(switch_ip), data=str(self.ip))
        self.adapter.sendto(request_packet, send_address)

        # receive ack
        ack = self.adapter.recvfrom(PACKET_SIZE)
        ackMessage = ack[0]
        # ackMessage = ack[0].decode().rstrip('\x00')
        self.recv_packets.append(ackMessage)
        # print(self.ip)
        # Check ack mode

    def take_input(self):
        '''
        Take command from stdin. Acceptable command is 'send'
        '''
        # time.sleep(0.5)
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                return
            else:
                
                self.send_command(user_input)


    def send_command(self, user_input):
        user_input_split = user_input.split(maxsplit=2) # prevent splitting data
        if len(user_input_split) != 3:
            return
        command = user_input_split[0]
        dest = user_input_split[1]
        data = user_input_split[2]
        # Create packet and send
        if command in 'send' and data[0] == '"' and data[len(data) - 1] == '"':
            data_packet = self.create_packet(mode=DATA_05, source_ip=str(self.ip), dest_ip=dest, 
                    data=data[1:(len(data) - 1)])
            self.adapter.sendto(data_packet, (LOCAL_HOST, self.switch_num))


    def run(self):

        self.greeting()
        thread_stdin = threading.Thread(target=self.take_input)
        thread_stdin.start()
        # # send discovery
        # discovery_packet = self.create_packet(DISCOVERY_01)
        # send_address = (LOCAL_HOST, self.switch_num)
        # self.adapter.sendto(discovery_packet, send_address)

        while True:
            message, _ = self.adapter.recvfrom(PACKET_SIZE)
            # print('receive ', end='')
            # for i in range(len(message)):
            #     print(message[i], end='.')
            #     if i == len(message) - 1:
            #         print('\n', end='')
            mode = message[11]
            dest_ip = message[:4]
            self.recv_packets.append(message)
            
            # if mode == OFFER_02:
            #     switch_ip = ipaddress.IPv4Address(message[:4]) 
            #     self.switch_ips.append(switch_ip)
            #     self.ip = ipaddress.IPv4Address(int.from_bytes(message[12:16], byteorder='big'))

            #     # send request:
            #     request_packet = self.create_packet(REQUEST_03, dest_ip=str(switch_ip), data=str(self.ip))
            #     self.adapter.sendto(request_packet, send_address)
            #     self.send_packets.append(request_packet)

            # if mode == ACK_04:
            #     self.ack = True

            if mode == ASK_06:
                # Send 0x07 packet
                # dest_ip = int.from_bytes(dest_ip, byteorder='big')
                dest = ipaddress.ip_address(dest_ip)
                mode_7_packet = self.create_packet(READY_07, source_ip=str(self.ip), dest_ip=str(dest), data='')
                self.adapter.sendto(mode_7_packet, (LOCAL_HOST, self.switch_num))
                self.ready = True

            elif mode == DATA_05:
                # if self.ready:
                    source_ip = message[:4]
                    packet_data = message[12:].decode()
                    source_ip = ipaddress.ip_address(int.from_bytes(source_ip, byteorder='big'))
                    print('\b\bReceived from {}: {}'.format(
                        str(source_ip), 
                        packet_data), flush=True)
                    print('> ', end='', flush=True)
                # self.within_5_sec = time.time()

            elif mode == FRAGMENT_0A:
                source_ip = ipaddress.ip_address(message[:4])
                if source_ip not in self.switch_message:
                    self.switch_message[source_ip] = [""]
                self.switch_message[source_ip][0] += message[12:].decode()

            elif mode == FRAGMENT_END_0B:
                source_ip = ipaddress.ip_address(message[:4])
                self.switch_message[source_ip][0] += message[12:].decode()
                print('\b\bReceived from {}: {}'.format(
                    str(source_ip), 
                    self.switch_message[source_ip][0], flush=True))
                self.switch_message[source_ip][0] = ""
                print('> ', end='', flush=True)

            # elif mode == DATA and time.time() - self.within_5_sec < 5 and self.within_5_sec != 0:
            #     source_ip = message[:4]
            #     packet_data = message[12:].decode()
            #     source_ip = ipaddress.ip_address(source_ip)
            #     print('\b\bReceived from {}: {}'.format(
            #         str(source_ip), 
            #         packet_data), flush=True)
                # print('> ', end='', flush=True)
            
        


def main():
    adapter = Adapter()
    adapter.run()

if __name__ == "__main__":
    main()