#!/usr/bin/env python3
"""
MQTT Topology - Uses EXTERNAL Ryu controller on 127.0.0.1:6633
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time
import sys

def clean_mqtt_network():
    """Create MQTT network using external Ryu controller"""
    
    info('*** Creating MQTT SDN Network\n')
    info('*** Connecting to Ryu controller at 127.0.0.1:6633\n')
    
    # Create network with REMOTE controller only
    net = Mininet(controller=RemoteController,
                  switch=OVSSwitch,
                  link=TCLink,
                  autoSetMacs=True,
                  autoStaticArp=True)
    
    # Add remote controller (pointing to your running Ryu)
    info('*** Adding remote controller\n')
    c0 = net.addController('c0', 
                          controller=RemoteController, 
                          ip='127.0.0.1', 
                          port=6633,
                          protocols='OpenFlow13')
    
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')
    
    info('*** Adding hosts\n')
    # MQTT Broker
    broker = net.addHost('broker', 
                        ip='10.0.0.1/24', 
                        mac='00:00:00:00:00:01')
    
    # Normal MQTT clients
    pub1 = net.addHost('pub1', 
                      ip='10.0.0.2/24', 
                      mac='00:00:00:00:00:02')
    
    sub1 = net.addHost('sub1', 
                      ip='10.0.0.3/24', 
                      mac='00:00:00:00:00:03')
    
    # Attacker
    attacker = net.addHost('attacker', 
                          ip='10.0.0.4/24', 
                          mac='00:00:00:00:00:04')
    
    info('*** Creating links\n')
    net.addLink(broker, s1, bw=100)
    net.addLink(pub1, s1, bw=100)
    net.addLink(sub1, s1, bw=100)
    net.addLink(attacker, s1, bw=100)
    
    info('*** Starting network\n')
    net.start()
    
    info('*** Starting MQTT broker\n')
    # Start Mosquitto on broker host
    broker.cmd('mosquitto -d')
    time.sleep(3)  # Wait for broker to start
    
    # Verify broker is running
    result = broker.cmd('netstat -tlnp 2>/dev/null | grep :1883 || echo "Port not found"')
    if '1883' in result:
        info('*** MQTT broker is running on port 1883\n')
    else:
        info('!!! WARNING: MQTT broker may not have started\n')
        # Try alternative startup
        broker.cmd('pkill mosquitto 2>/dev/null')
        broker.cmd('mosquitto -d')
        time.sleep(2)
    
    # Display network information
    info('\n' + '='*60 + '\n')
    info('*** MQTT SDN Network Ready\n')
    info('='*60 + '\n')
    info('IMPORTANT: Ensure Ryu controller is running in another terminal\n')
    info('Controller should be at: 127.0.0.1:6633\n\n')
    info('Host IPs:\n')
    info('  Broker:    10.0.0.1\n')
    info('  Publisher: 10.0.0.2\n')
    info('  Subscriber:10.0.0.3\n')
    info('  Attacker:  10.0.0.4\n\n')
    info('Test commands:\n')
    info('  mininet> pub1 ping -c 3 broker\n')
    info('  mininet> pub1 mosquitto_pub -h 10.0.0.1 -t test -m "hello"\n')
    info('  mininet> sub1 mosquitto_sub -h 10.0.0.1 -t test &\n')
    info('='*60 + '\n\n')
    
    # Start Mininet CLI
    CLI(net)
    
    # Cleanup
    info('*** Stopping network\n')
    broker.cmd('pkill mosquitto 2>/dev/null')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    clean_mqtt_network()
