from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

#import mytest
from custom_SimpleSwitch13 import SimpleSwitch13
from dnn_class import SimpleDNN
import torch

class SDNController(SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SDNController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.model = SimpleDNN()
        self.model.load_state_dict(torch.load('dnn_discriminator_real_data'))
        self.model.eval()
        self.logger.debug('model loaded', self.model)
        print(f'model loaded: {self.model}')



    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        # Features Needed: 
        # protocol_type
        protocol_dict = {'tcp': 0, 'udp': 1, 'icmp': 2} 
        # service
        service_dict = {'ftp_data': 0, 'other': 1, 'private': 2, 'http': 3, 'remote_job': 4, 'name': 5, 'netbios_ns': 6, 'eco_i': 7, 'mtp': 8, 'telnet': 9, 'finger': 10, 'domain_u': 11, 'supdup': 12, 'uucp_path': 13, 'Z39_50': 14, 'smtp': 15, 'csnet_ns': 16, 'uucp': 17, 'netbios_dgm': 18, 'urp_i': 19, 'auth': 20, 'domain': 21, 'ftp': 22, 'bgp': 23, 'ldap': 24, 'ecr_i': 25, 'gopher': 26, 'vmnet': 27, 'systat': 28, 'http_443': 29, 'efs': 30, 'whois': 31, 'imap4': 32, 'iso_tsap': 33, 'echo': 34, 'klogin': 35, 'link': 36, 'sunrpc': 37, 'login': 38, 'kshell': 39, 'sql_net': 40, 'time': 41, 'hostnames': 42, 'exec': 43, 'ntp_u': 44, 'discard': 45, 'nntp': 46, 'courier': 47, 'ctf': 48, 'ssh': 49, 'daytime': 50, 'shell': 51, 'netstat': 52, 'pop_3': 53, 'nnsp': 54, 'IRC': 55, 'pop_2': 56, 'printer': 57, 'tim_i': 58, 'pm_dump': 59, 'red_i': 60, 'netbios_ssn': 61, 'rje': 62, 'X11': 63, 'urh_i': 64, 'http_8001': 65, 'aol': 66, 'http_2784': 67, 'tftp_u': 68, 'harvest': 69}
        # flag
        flag_dict = {'SF': 0, 'S0': 1, 'REJ': 2, 'RSTR': 3, 'SH': 4, 'RSTO': 5, 'S1': 6, 'RSTOS0': 7, 'S3': 8, 'S2': 9, 'OTH': 10}
        # count
        count = 0
        # logged_in 
        logged_in = 0
        # serror_rate
        total_syn = 0
        syn_errors = 0
        serror_rate = 0
        # srv_serror_rate
        srv_serror_rate = 0
        # same_srv_rate
        same_srv_rate = 0
        # dst_host_srv_count
        dst_host_srv_count = 0
        # dst_host_same_srv_rate
        dst_host_same_srv_rate = 0
        # dst_host_serror_rate
        dst_host_serror_rate = 0
        # dst_host_srv_serror_rate 
        dst_host_serror_rate = 0

        # Get data from msg

        for stat in [flow for flow in body]: 
            try: 
                ip_proto = stat.match['ip_proto']
                print('Controller deciding on flow: ')
                print(f'protocol: {ip_proto}')
            except: 
                print('message not in ip_proto')
                continue
            flag = stat.flags
            count += 1


            if stat.match['ip_proto'] == 1: 
                #icmp
                protocol = protocol_dict['icmp']
                service = service_dict['other']

            elif stat.match['ip_proto'] == 6: 
                #tcp
                protocol = protocol_dict['tcp']
                x = stat.match['tcp_src']
                y = stat.match['tcp_dst']
                print(y)
                service_dict = {22:'ssh'}
                service = service_dict[y]

            elif stat.match['ip_proto'] == 17: 
                #udp
                protocol = protocol_dict['udp']
                x = stat.match['udp_src']
                y = stat.match['udp_dst']
                print(y)
                service_dict = {22:'ssh'}
                service = service_dict[y]

            # Get rest of data from controller vars

            #try: 
            #    pkt_count_per_sec = stat.packet_count/stat.duration_sec
            #except:
            #    pkt_count_per_sec = 0

            #try: 
            #    #stat.byte_count
            #    pass
            #except:
            #    pass

            # Predict pkt class based on above data
            pkt_is_attack = False

            model_input = torch.zeros(1,12,dtype=torch.double)
            # protocol, service, flag, 
            model_input[0,0] = protocol
            model_input[0,1] = service
            model_input[0,2] = flag
            model_input[0,3] = count
            model_input[0,4] = logged_in
            model_input[0,5] = serror_rate
            model_input[0,6] = srv_serror_rate
            model_input[0,7] = same_srv_rate
            model_input[0,8] = dst_host_srv_count
            model_input[0,9] = dst_host_same_srv_rate
            model_input[0,10] = dst_host_serror_rate 
            model_input[0,11] = dst_host_serror_rate

            if (self.model(model_input.float())>.02):
                pkt_is_attack = True

            if pkt_is_attack: 
                print(f'ATTACK DETECTED   ATTACK DETECTED   ATTACK DETECTED   ATTACK DETECTED   ATTACK DETECTED   ATTACK DETECTED')
            else:
                print(f'Benign Traffic')
        #print('===============================================================')
















        #self.logger.info('datapath         '
        #                'in-port  eth-dst           '
        #                'out-port packets  bytes')
        #self.logger.info('---------------- '
        #                '-------- ----------------- '
        #                '-------- -------- --------')
        #for stat in sorted([flow for flow in body if flow.priority == 1],
        #                    key=lambda flow: (flow.match['in_port'],
        #                                    flow.match['eth_dst'])):
        #    self.logger.info('%016x %8x %17s %8x %8d %8d',
        #                    ev.msg.datapath.id,
        #                    stat.match['in_port'], stat.match['eth_dst'],
        #                    stat.instructions[0].actions[0].port,
        #                    stat.packet_count, stat.byte_count)

#    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
#    def _port_stats_reply_handler(self, ev):
#        body = ev.msg.body
#        print('new PORT stats reply msg body: ')
#        print('')
#        print('===============================================================')
#        print(type(ev))
#        print(type(ev.msg))
#        print(type(ev.msg.body))
#        print('===============================================================')
#
#        #self.logger.info('datapath         port     '
#        #                'rx-pkts  rx-bytes rx-error '
#        #                'tx-pkts  tx-bytes tx-error')
#        #self.logger.info('---------------- -------- '
#        #                '-------- -------- -------- '
#        #                '-------- -------- --------')
#        #for stat in sorted(body, key=attrgetter('port_no')):
#        #    self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
#        #                    ev.msg.datapath.id, stat.port_no,
#        #                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
#        #                    stat.tx_packets, stat.tx_bytes, stat.tx_errors)
