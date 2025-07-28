from datetime import datetime
import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP

# A dictionary to hold ICMP flood tracking data
# It's kept here to be self-contained within the detection logic.
icmp_tracker = defaultdict(list)

class Rule:
    """
    Represents and parses a single IDS rule.
    Example rule string: "TCP_PORT=80|Possible HTTP Traffic|Low"
    """
    def __init__(self, rule_string):
        try:
            condition_part, self.message, self.severity = rule_string.strip().split('|')
            self.condition_type, self.condition_value = condition_part.split('=', 1) if '=' in condition_part else condition_part.split('>', 1)
            self.condition_type = self.condition_type.upper()
            
            # For ICMP_FLOOD, parse the threshold and period
            if self.condition_type == 'ICMP_FLOOD':
                self.threshold, self.period = map(int, self.condition_value.replace('s','').split('/'))
            else:
                self.condition_value = int(self.condition_value)

        except (ValueError, IndexError) as e:
            print(f"Error parsing rule: '{rule_string}'. Malformed. Skipping. Error: {e}")
            raise ValueError("Invalid rule format")

    def matches(self, packet_info):
        """Checks if a packet matches this rule."""
        proto = packet_info.get('proto')
        dport = packet_info.get('dport')
        src_ip = packet_info.get('src')

        if self.condition_type == 'TCP_PORT' and proto == 'TCP':
            return dport == self.condition_value
        
        if self.condition_type == 'UDP_PORT' and proto == 'UDP':
            return dport == self.condition_value
            
        if self.condition_type == 'ICMP_FLOOD' and proto == 'ICMP':
            now = time.time()
            # Clean up old timestamps outside the flood detection period
            icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if now - t <= self.period]
            icmp_tracker[src_ip].append(now)
            
            # If count exceeds threshold, it's a match
            if len(icmp_tracker[src_ip]) > self.threshold:
                icmp_tracker[src_ip] = [] # Clear tracker for this source to prevent immediate re-alerts
                return True
        
        return False

class AlertEngine:
    """
    Manages the set of rules and evaluates packets against them.
    """
    def __init__(self, rules_file="rules.txt"):
        self.rules = self._load_rules(rules_file)

    def _load_rules(self, rules_file):
        """Loads and parses rules from a given file."""
        loaded_rules = []
        try:
            with open(rules_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        loaded_rules.append(Rule(line))
                    except ValueError:
                        continue # Silently skip malformed rules as Rule class already prints an error
            print(f"Successfully loaded {len(loaded_rules)} rules.")
        except FileNotFoundError:
            print(f"Error: Rules file '{rules_file}' not found. No rules will be active.")
        return loaded_rules

    def check_packet(self, packet):
        """
        Checks a single packet against all loaded rules and returns an alert if a match is found.
        """
        packet_info = self._extract_packet_info(packet)
        if not packet_info:
            return None

        for rule in self.rules:
            if rule.matches(packet_info):
                return self._create_alert(rule, packet_info)
        
        return None

    def _extract_packet_info(self, packet):
        """Extracts relevant information from a Scapy packet into a dictionary."""
        if not packet.haslayer(IP):
            return None

        info = {'src': packet[IP].src, 'dst': packet[IP].dst, 'proto': None, 'sport': None, 'dport': None}
        
        if packet.haslayer(TCP):
            info.update(proto='TCP', sport=packet[TCP].sport, dport=packet[TCP].dport)
        elif packet.haslayer(UDP):
            info.update(proto='UDP', sport=packet[UDP].sport, dport=packet[UDP].dport)
        elif packet.haslayer(ICMP):
            info.update(proto='ICMP')
        
        return info

    def _create_alert(self, rule, packet_info):
        """Creates a formatted alert dictionary."""
        return {
            "Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Source": packet_info['src'],
            "Destination": packet_info['dst'],
            "Protocol": packet_info['proto'],
            "Severity": rule.severity,
            "Message": rule.message
        }
