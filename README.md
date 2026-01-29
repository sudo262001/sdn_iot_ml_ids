# sdn_iot_ids
## Final Year's Junior Project 
### Nagham Ashkar & Moustafa Seifo

## Abstract

This project investigates the security of MQTT-based IoT networks by designing and implementing an intrusion detection and mitigation framework based on Software-Defined Networking (SDN). The proposed approach leverages the centralized control and global visibility provided by SDN to dynamically detect malicious traffic patterns and enforce mitigation policies at the network level. Instead of relying solely on traditional host-based defenses, the system integrates a network-based intrusion detection system (IDS) to monitor MQTT traffic in real time.

In the proposed architecture, Suricata is employed as a signature-based IDS to analyze MQTT traffic and detect known attack patterns and protocol violations, including publish flooding and malformed MQTT control packets. Upon detecting a security alert, the SDN controller reacts by dynamically installing flow rules in the OpenFlow switch to block malicious traffic originating from the detected source for a predefined period of time. This tight integration between the IDS and the SDN controller enables automated and rapid mitigation without manual intervention.

The system is implemented and evaluated in a virtualized testbed using Mininet, Open vSwitch, the Ryu SDN controller, and a Mosquitto MQTT broker. Experimental results demonstrate that the proposed solution is capable of detecting and mitigating several MQTT-specific attacks in real time, effectively reducing their impact on the broker and the network. The project highlights the feasibility and effectiveness of combining SDN with signature-based intrusion detection to enhance the security of MQTT-based IoT environments, while also identifying potential challenges and directions for future improvements.


## Architecture

![IMG_20260129_054418_717](https://github.com/user-attachments/assets/bdff9d34-7505-479d-a0d5-28626c0357f5)

