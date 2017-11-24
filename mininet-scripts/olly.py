import Queue
import socket
import struct
import threading
import time
import thread
import pickle
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types

def send_one_message(sock, data):
    length = len(data)
    sock.send(struct.pack('!I', length))
    sock.send(data)


def recv_one_message(sock):
    lengthbuf = recvall(sock, 4)
    length, = struct.unpack('!I', lengthbuf)
    return recvall(sock, length)


def recvall(sock, count):
    buf = b''
    while count:
        newbuf = sock.recv(count)
        if not newbuf: return None
        buf += newbuf
        count -= len(newbuf)
    return buf

def clientSocket(queue):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a socket object
    host = socket.gethostname()  # Get local machine name
    port = 1508  # Reserve a port for your service.

    try:
        s.connect((host, port))
        try:
            print 'Connected to FDRS'
            data = recv_one_message(s)
            rulesdict = pickle.loads(data)
            queue.put(rulesdict)
        finally:
            s.close  # Close the socket when done
            print 'Socket closed'
    except:
        print "Cannot connect to FDRS"

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        try:
            queue = Queue.Queue()
            myThread = threading.Thread(target=clientSocket, args=(queue,),)
            myThread.start()
            myThread.join()
            self.rulesdict = queue.get(False)
            print "Rules successfully loaded from FDRS"
        except:
            self.rulesdict = {}
            print "Cannot load rules"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, 0)

    def add_flow(self, datapath, priority, match, actions, policy):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if policy:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        policy = 0

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_proto = pkt.get_protocol(ipv4.ipv4)
        arp_proto = pkt.get_protocol(arp.arp)

        # if ipv4_proto is not None and datapath.id == 3:
        #     print pkt
        #     print ""

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            # if datapath.id == 3:
            #     print ipv4_proto
            #     print ""
            if ipv4_proto is not None:
                proto_in_packet = in_proto.IPPROTO_IP
                icmp_proto = pkt.get_protocol(icmp.icmp)
                tcp_proto = pkt.get_protocol(tcp.tcp)
                udp_proto = pkt.get_protocol(udp.udp)
                if icmp_proto is not None:
                    proto_in_packet = in_proto.IPPROTO_ICMP
                if tcp_proto is not None:
                    proto_in_packet = in_proto.IPPROTO_TCP
                if udp_proto is not None:
                    proto_in_packet = in_proto.IPPROTO_UDP
                for item in self.rulesdict.keys():
                    if ipv4_proto.src in item[0] and ipv4_proto.dst in item[1]:
                        for data in self.rulesdict[item]:
                            #print data
                            if data[0] == 'P':
                                break
                            if data[1] == "IP" and data[0] == 'D' and ipv4_proto is not None:
                                policy = 1
                                print "IP packet blocked: "
                                print pkt
                                break
                            if data[1] == "ICMP" and data[0] == 'D' and icmp_proto is not None:
                                policy = 1
                                print "ICMP packet blocked: "
                                print pkt
                                break
                            if data[1] == "TCP" and data[0] == 'D' and tcp_proto is not None:
                                policy = 1
                                print "TCP packet blocked: "
                                print pkt
                                break
                            if data[1] == "UDP" and data[0] == 'D' and udp_proto is not None:
                                policy = 1
                                print "UDP packet blocked: "
                                print pkt
                                break

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            if ipv4_proto is not None:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_IP,
                    ip_proto=proto_in_packet,
                    ipv4_src=ipv4_proto.src,
                    ipv4_dst=ipv4_proto.dst)
                priority = 3
            elif arp_proto is not None:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=ether_types.ETH_TYPE_ARP,
                    arp_op=arp_proto.opcode,
                    arp_spa=arp_proto.src_ip,
                    arp_tpa=arp_proto.dst_ip)
                priority = 2
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                priority = 1
            self.add_flow(datapath, priority, match, actions, policy)

        if not policy:
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
