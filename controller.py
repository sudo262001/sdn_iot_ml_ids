#!/usr/bin/env python3
"""
Complete Feature Extraction - Captures all packet types
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from datetime import datetime
import json
import time
from collections import defaultdict

class CompleteFeaturesController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(CompleteFeaturesController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.features = []
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'start_time': time.time(),
            'last_time': time.time(),
            'packet_sizes': []
        })
        print("\n" + "="*60)
        print("COMPLETE FEATURE EXTRACTION CONTROLLER")
        print("Capturing ALL packet types")
        print("="*60 + "\n")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)
        
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Switch {datapath.id} connected - Ready to capture")
    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def parse_packet(self, raw_data):
        """Parse packet for MQTT and TCP features"""
        try:
            data = bytes(raw_data)
            result = {'raw_length': len(data)}
            
            # Always try to find MQTT
            for i in range(40, min(100, len(data) - 1)):
                byte1 = data[i]
                byte2 = data[i + 1] if i + 1 < len(data) else 0
                
                packet_type = (byte1 >> 4) & 0x0F
                if 1 <= packet_type <= 14:
                    mqtt_types = {
                        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH",
                        4: "PUBACK", 5: "PUBREC", 6: "PUBREL",
                        7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
                        10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ",
                        13: "PINGRESP", 14: "DISCONNECT"
                    }
                    
                    result.update({
                        'mqtt_detected': True,
                        'mqtt_type': packet_type,
                        'mqtt_type_name': mqtt_types.get(packet_type, f"UNKNOWN_{packet_type}"),
                        'mqtt_remaining_len': byte2,
                        'found_at': i
                    })
                    
                    # Try to parse PUBLISH
                    if packet_type == 3 and i + 4 < len(data):
                        topic_len = (data[i+2] << 8) | data[i+3]
                        if i + 4 + topic_len < len(data):
                            try:
                                topic = data[i+4:i+4+topic_len].decode('utf-8', errors='ignore')
                                result['topic'] = topic
                                
                                msg_start = i + 4 + topic_len
                                if msg_start < len(data):
                                    message = data[msg_start:].decode('utf-8', errors='ignore')[:50]
                                    result['message'] = message
                            except:
                                pass
                    break
            else:
                result['mqtt_detected'] = False
            
            return result
            
        except Exception as e:
            return {'error': str(e), 'mqtt_detected': False}
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth:
            return
        
        # Learning switch
        src = eth.src
        dst = eth.dst
        dpid = datapath.id
        
        if dpid not in self.mac_to_port:
            self.mac_to_port[dpid] = {}
        
        self.mac_to_port[dpid][src] = in_port
        
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
        
        # === COMPLETE FEATURE EXTRACTION ===
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        if ip_pkt and tcp_pkt:
            current_time = time.time()
            flow_key = f"{ip_pkt.src}:{tcp_pkt.src_port}"
            
            # Update statistics
            stats = self.flow_stats[flow_key]
            time_diff = current_time - stats['last_time']
            stats['last_time'] = current_time
            stats['packet_count'] += 1
            stats['packet_sizes'].append(len(msg.data))
            
            # Parse packet
            parsed = self.parse_packet(msg.data)
            
            # Create feature entry
            feature = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': ip_pkt.src,
                'dst_ip': ip_pkt.dst,
                'src_port': tcp_pkt.src_port,
                'dst_port': tcp_pkt.dst_port,
                'packet_length': len(msg.data),
                'ip_total_length': ip_pkt.total_length,
                'tcp_window_size': tcp_pkt.window_size,
                'tcp_flags': tcp_pkt.bits,
                'flow_packet_count': stats['packet_count'],
                'flow_duration': current_time - stats['start_time'],
                'inter_arrival_time': time_diff if stats['packet_count'] > 1 else 0,
                'avg_packet_size': sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0
            }
            
            # Add parsed MQTT info
            feature.update(parsed)
            
            # Log based on what we found
            if tcp_pkt.dst_port == 1883 or tcp_pkt.src_port == 1883:
                if parsed.get('mqtt_detected'):
                    mqtt_type = parsed.get('mqtt_type_name', 'UNKNOWN')
                    direction = "->" if tcp_pkt.dst_port == 1883 else "<-"
                    log_msg = f"[{datetime.now().strftime('%H:%M:%S')}] MQTT {mqtt_type}: {ip_pkt.src}:{tcp_pkt.src_port} {direction} {ip_pkt.dst}:{tcp_pkt.dst_port}"
                    
                    if 'topic' in parsed:
                        log_msg += f" Topic: {parsed['topic']}"
                    if 'message' in parsed:
                        log_msg += f" Msg: {parsed['message']}"
                    
                    print(log_msg)
                else:
                    # MQTT port but no MQTT detected (TCP handshake/control)
                    tcp_flag_names = []
                    if tcp_pkt.bits & 0x02: tcp_flag_names.append("SYN")
                    if tcp_pkt.bits & 0x10: tcp_flag_names.append("ACK")
                    if tcp_pkt.bits & 0x08: tcp_flag_names.append("PSH")
                    if tcp_pkt.bits & 0x01: tcp_flag_names.append("FIN")
                    
                    flags_str = '+'.join(tcp_flag_names) if tcp_flag_names else str(tcp_pkt.bits)
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] TCP {flags_str}: {ip_pkt.src}:{tcp_pkt.src_port} -> {ip_pkt.dst}:{tcp_pkt.dst_port} Size: {len(msg.data)}B")
            
            # Save feature
            self.features.append(feature)
            
            # Save periodically
            if len(self.features) % 3 == 0:
                self.save_features()
    
    def save_features(self):
        """Save features to file"""
        try:
            with open('/tmp/mqtt_features.json', 'w') as f:
                json.dump(self.features[-100:], f, indent=2)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Saved {len(self.features)} features")
        except Exception as e:
            print(f"Error saving: {e}")

if __name__ == '__main__':
    print("Run: ryu-manager complete_features.py")
