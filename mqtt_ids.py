#!/usr/bin/env python3
import json
import time
import threading
import subprocess

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

class SimpleL2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ---- IDS integration config ----
    EVE_JSON_PATH = "/var/log/suricata/eve.json"
    DROP_DURATION_SEC = 60
    DROP_COOLDOWN_SEC = 2  # prevent repeated installs for same src_ip in short time window

    def __init__(self, *args, **kwargs):
        super(SimpleL2Switch, self).__init__(*args, **kwargs)

        # L2 learning state
        self.mac_to_port = {}   # {dpid: {mac: port}}

        # Keep datapaths so we can install drops when alerts arrive
        self.datapaths = {}     # {dpid: datapath}

        # Cooldown tracking per src_ip
        self._last_drop_src = {}  # {src_ip: last_time}

        # Start background thread to tail eve.json
        t = threading.Thread(target=self._tail_suricata_eve_forever, daemon=True)
        t.start()

        self.logger.info("Ryu switch started. Tailing Suricata eve.json: %s", self.EVE_JSON_PATH)

    # ---------------- OpenFlow helpers ----------------
    def add_flow(self, datapath, priority, match, actions=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if actions:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        else:
            inst = []  # DROP

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def install_drop_from_src_ip(self, datapath, src_ip, duration_sec):
        """
        Drop ANY IPv4 traffic coming from src_ip for duration_sec.
        """
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800,   # IPv4
            ipv4_src=src_ip
        )
        self.add_flow(datapath, priority=200, match=match, actions=None, hard_timeout=duration_sec)

    # ---------------- Suricata eve.json tail ----------------
    def _tail_suricata_eve_forever(self):
        """
        Continuously reads appended JSON lines from eve.json and reacts to ANY alert.
        Uses: tail -n +1 -F /var/log/suricata/eve.json
        """
        cmd = ["bash", "-lc", f"tail -n +1 -F {self.EVE_JSON_PATH}"]
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        except Exception as e:
            self.logger.error("Failed to tail eve.json: %s", e)
            return

        for line in p.stdout:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except Exception:
                continue

            # Only act on Suricata alert events
            if event.get("event_type") != "alert":
                continue

            src_ip = event.get("src_ip")
            if not src_ip:
                continue

            alert = event.get("alert", {})
            signature = str(alert.get("signature", ""))
            sid = alert.get("signature_id", alert.get("sid", "unknown"))

            # Cooldown to avoid spamming flow table for the same attacker
            now = time.monotonic()
            last = self._last_drop_src.get(src_ip, 0.0)
            if now - last < self.DROP_COOLDOWN_SEC:
                continue
            self._last_drop_src[src_ip] = now

            if not self.datapaths:
                self.logger.warning("Suricata alert seen but no switch connected yet. src_ip=%s sid=%s", src_ip, sid)
                continue

            for dpid, dp in self.datapaths.items():
                self.install_drop_from_src_ip(dp, src_ip, self.DROP_DURATION_SEC)
                self.logger.warning(
                    "DROP INSTALLED (60s) on dpid=%s | src_ip=%s | sid=%s | signature=%s",
                    dpid, src_ip, sid, signature
                )

    # ---------------- Switch connect ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Install table-miss rule: send unmatched packets to controller.
        Also store datapath for IDS mitigation.
        """
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected (dpid=%s). Table-miss installed.", datapath.id)

    # ---------------- PacketIn (Learning Switch) ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
