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

queue = Queue.Queue()
flows = {}
#rulesdict = {}

def update(rulesdict, action):
    print "Update of flow tables"
    print action
    print rulesdict
    rule_proto = 0
    for item in rulesdict.keys():
        for datapath in flows.keys():
            for mod in flows[datapath]:
                match = mod.match
                try:
                    if match['ipv4_src'] == item[0] and match['ipv4_dst'] == item[1]:
                        for data in rulesdict[item]:
                            if data[1] == "IP":
                                rule_proto = in_proto.IPPROTO_IP
                            elif data[1] == "ICMP":
                                rule_proto = in_proto.IPPROTO_ICMP
                            elif data[1] == "TCP":
                                rule_proto = in_proto.IPPROTO_TCP
                            elif data[1] == "UDP":
                                rule_proto = in_proto.IPPROTO_UDP
                            if match['ip_proto'] == rule_proto:
                                try:
                                    port = mod.instructions[0].actions[0].port
                                    if data[0] == 'D':
                                        print "Found mismatch, applying new rule..."
                                        ofproto = datapath.ofproto
                                        new_mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath,
                                            match=match,
                                            cookie=0,
                                            command=ofproto.OFPFC_DELETE,
                                            idle_timeout=0,
                                            hard_timeout=0,
                                            priority=mod.priority,
                                            out_port=ofproto.OFPP_ANY,
                                            out_group=ofproto.OFPG_ANY)
                                        datapath.send_msg(new_mod)
                                        print 'Rule applied on %d', datapath.id
                                    if action == "del":
                                        print "Found match on deleting rule. Deleting..."
                                        ofproto = datapath.ofproto
                                        new_mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath,
                                            match=match,
                                            cookie=0,
                                            command=ofproto.OFPFC_DELETE,
                                            idle_timeout=0,
                                            hard_timeout=0,
                                            priority=mod.priority,
                                            out_port=ofproto.OFPP_ANY,
                                            out_group=ofproto.OFPG_ANY)
                                        datapath.send_msg(new_mod)
                                        print "Delete successful"
                                except:
                                    if data[0] == 'P':
                                        print "Found mismatch, applying new rule..."
                                        ofproto = datapath.ofproto
                                        new_mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath,
                                            match=match,
                                            cookie=0,
                                            command=ofproto.OFPFC_DELETE,
                                            idle_timeout=0,
                                            hard_timeout=0,
                                            priority=mod.priority,
                                            out_port=ofproto.OFPP_ANY,
                                            out_group=ofproto.OFPG_ANY)
                                        datapath.send_msg(new_mod)
                                        print 'Rule applied on %d', datapath.id
                                    if action == "del":
                                        print "Found match on deleting rule. Deleting..."
                                        ofproto = datapath.ofproto
                                        new_mod = datapath.ofproto_parser.OFPFlowMod(
                                            datapath=datapath,
                                            match=match,
                                            cookie=0,
                                            command=ofproto.OFPFC_DELETE,
                                            idle_timeout=0,
                                            hard_timeout=0,
                                            priority=mod.priority,
                                            out_port=ofproto.OFPP_ANY,
                                            out_group=ofproto.OFPG_ANY)
                                        datapath.send_msg(new_mod)
                                        print "Delete successful"
                except:
                    pass




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

def serverSocket(queue):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Vytvorenie soketu
    host = socket.gethostname()  # Nazov lokalneho stroja
    port = 1508  # Rezervovanie portu pre komunikaciu
    s.bind((host, port))  # Priradenie hosta na port

    while 1:
        s.listen(5)  # Cakanie na pripojenie klienta
        print 'Waiting for connection...'
        c, addr = s.accept()  # Vytvorenie spojenia s klientom
        try:
            print 'Got connection from', addr
            data = recv_one_message(c)
            action = pickle.loads(data)
            data = recv_one_message(c)
            rulesdict = pickle.loads(data)
            tuple = (action, rulesdict)
            queue.put(tuple)
            update(rulesdict, action)
        finally:
            c.close()
            print 'Client disconnected'

class SimpleSwitch14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch14, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        try:
            myThread = threading.Thread(target=serverSocket, args=(queue,),)
            myThread.start()
            #myThread.join()
            action, self.rulesdict = queue.get(timeout=5)
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
        if datapath not in flows:
            flows[datapath] = [mod]
        else:
            flows[datapath].append(mod)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        try:
            action, rule = queue.get(False)
            if action == "add":
                for item in rule.keys():
                    if item not in self.rulesdict:
                        self.rulesdict[item] = rule[item]
                    else:
                        self.rulesdict[item].append(rule[item])
            elif action == "del":
                for item in rule.keys():
                    for data in rule[item]:
                        self.rulesdict[item].remove(data)
                        if not self.rulesdict[item]:
                            del self.rulesdict[item]
            print self.rulesdict
        except:
            pass

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
            #print self.rulesdict
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
                                #print pkt
                                break
                            if data[1] == "ICMP" and data[0] == 'D' and icmp_proto is not None:
                                policy = 1
                                print "ICMP packet blocked: "
                                #print pkt
                                break
                            if data[1] == "TCP" and data[0] == 'D' and tcp_proto is not None:
                                policy = 1
                                print "TCP packet blocked: "
                                #print pkt
                                break
                            if data[1] == "UDP" and data[0] == 'D' and udp_proto is not None:
                                policy = 1
                                print "UDP packet blocked: "
                                #print pkt
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
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_dst=dst)
                priority = 1
            self.add_flow(datapath, priority, match, actions, policy)

        if not policy:
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)

    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             match)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'importance=%d cookie=%d packet_count=%d '
                         'byte_count=%d match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout,
                          stat.flags, stat.importance,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
        self.logger.debug('FlowStats: %s', flows)