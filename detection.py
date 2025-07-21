import pyshark
import joblib
import numpy as np
from collections import defaultdict
import time
import warnings
warnings.filterwarnings("ignore", category=UserWarning)


# Load model
model = joblib.load("model/rf_model.pkl")

# Live capture from your main interface
capture = pyshark.LiveCapture(interface='Wi-Fi', bpf_filter='ip')

# Flow tracking
flows = defaultdict(lambda: {
    'packets': [],
    'start_time': None,
    'last_seen': None
})

def get_flow_key(packet):
    """Create a unique flow identifier"""
    try:
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Get protocol and ports
            protocol = packet.transport_layer
            src_port = dst_port = 0
            
            if protocol and hasattr(packet[protocol.lower()], 'srcport'):
                src_port = int(packet[protocol.lower()].srcport)
                dst_port = int(packet[protocol.lower()].dstport)
            
            # Create bidirectional flow key
            flow_key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
            return f"{flow_key[0][0]}:{flow_key[0][1]}-{flow_key[1][0]}:{flow_key[1][1]}-{protocol}"
        
    except Exception as e:
        print(f"Error creating flow key: {e}")
    return None

def extract_flow_features(flow_data):
    """Extract comprehensive flow features matching training data"""
    try:
        packets = flow_data['packets']
        if len(packets) < 2:
            return None
            
        # Basic flow statistics
        packet_lengths = [p['length'] for p in packets]
        forward_packets = [p for p in packets if p['direction'] == 'forward']
        backward_packets = [p for p in packets if p['direction'] == 'backward']
        
        forward_lengths = [p['length'] for p in forward_packets]
        backward_lengths = [p['length'] for p in backward_packets]
        
        # Duration
        duration = flow_data['last_seen'] - flow_data['start_time']
        
        features = []
        
        # Flow duration
        features.append(duration)
        
        # Packet counts
        features.append(len(forward_packets))  # Total Fwd Packets
        features.append(len(backward_packets))  # Total Backward Packets
        features.append(sum(forward_lengths))   # Total Length of Fwd Packets
        features.append(sum(backward_lengths))  # Total Length of Bwd Packets
        
        # Forward packet statistics
        if forward_lengths:
            features.extend([
                max(forward_lengths),           # Fwd Packet Length Max
                min(forward_lengths),           # Fwd Packet Length Min
                np.mean(forward_lengths),       # Fwd Packet Length Mean
                np.std(forward_lengths)         # Fwd Packet Length Std
            ])
        else:
            features.extend([0, 0, 0, 0])
            
        # Backward packet statistics
        if backward_lengths:
            features.extend([
                max(backward_lengths),          # Bwd Packet Length Max
                min(backward_lengths),          # Bwd Packet Length Min
                np.mean(backward_lengths),      # Bwd Packet Length Mean
                np.std(backward_lengths)        # Bwd Packet Length Std
            ])
        else:
            features.extend([0, 0, 0, 0])
            
        # Flow bytes and packets per second
        if duration > 0:
            total_packets = len(packets)
            total_bytes = sum(packet_lengths)
            features.extend([
                total_bytes / duration,         # Flow Bytes/s
                total_packets / duration,       # Flow Packets/s
            ])
        else:
            features.extend([0, 0])
            
        # Flow IAT (Inter-arrival time) statistics
        if len(packets) > 1:
            iats = []
            for i in range(1, len(packets)):
                iat = packets[i]['timestamp'] - packets[i-1]['timestamp']
                iats.append(iat)
                
            features.extend([
                np.mean(iats),                  # Flow IAT Mean
                np.std(iats) if len(iats) > 1 else 0,  # Flow IAT Std
                max(iats),                      # Flow IAT Max
                min(iats)                       # Flow IAT Min
            ])
        else:
            features.extend([0, 0, 0, 0])
            
        # Forward/Backward IAT statistics
        if len(forward_packets) > 1:
            fwd_iats = []
            for i in range(1, len(forward_packets)):
                iat = forward_packets[i]['timestamp'] - forward_packets[i-1]['timestamp']
                fwd_iats.append(iat)
            
            features.extend([
                sum(fwd_iats),                  # Fwd IAT Total
                np.mean(fwd_iats),              # Fwd IAT Mean
                np.std(fwd_iats) if len(fwd_iats) > 1 else 0,  # Fwd IAT Std
                max(fwd_iats),                  # Fwd IAT Max
                min(fwd_iats)                   # Fwd IAT Min
            ])
        else:
            features.extend([0, 0, 0, 0, 0])
            
        if len(backward_packets) > 1:
            bwd_iats = []
            for i in range(1, len(backward_packets)):
                iat = backward_packets[i]['timestamp'] - backward_packets[i-1]['timestamp']
                bwd_iats.append(iat)
                
            features.extend([
                sum(bwd_iats),                  # Bwd IAT Total
                np.mean(bwd_iats),              # Bwd IAT Mean
                np.std(bwd_iats) if len(bwd_iats) > 1 else 0,  # Bwd IAT Std
                max(bwd_iats),                  # Bwd IAT Max
                min(bwd_iats)                   # Bwd IAT Min
            ])
        else:
            features.extend([0, 0, 0, 0, 0])
            
        # Additional features to reach 78 (adjust based on your training features)
        # PSH, URG, FIN, SYN, RST, ACK flags
        tcp_packets = [p for p in packets if 'tcp' in p and p['tcp']]
        if tcp_packets:
            flags = {
                'psh': sum(1 for p in tcp_packets if p['tcp'].get('flags_psh', 0) == '1'),
                'urg': sum(1 for p in tcp_packets if p['tcp'].get('flags_urg', 0) == '1'),
                'fin': sum(1 for p in tcp_packets if p['tcp'].get('flags_fin', 0) == '1'),
                'syn': sum(1 for p in tcp_packets if p['tcp'].get('flags_syn', 0) == '1'),
                'rst': sum(1 for p in tcp_packets if p['tcp'].get('flags_rst', 0) == '1'),
                'ack': sum(1 for p in tcp_packets if p['tcp'].get('flags_ack', 0) == '1'),
            }
            features.extend([
                flags['psh'], flags['urg'], flags['fin'],
                flags['syn'], flags['rst'], flags['ack']
            ])
        else:
            features.extend([0, 0, 0, 0, 0, 0])
            
        # Header lengths, window sizes, etc.
        if tcp_packets:
            header_lengths = [int(p['tcp'].get('hdr_len', 0)) for p in tcp_packets if 'tcp' in p]
            features.extend([
                np.mean(header_lengths) if header_lengths else 0,  # Avg header length
                max(header_lengths) if header_lengths else 0,     # Max header length
            ])
        else:
            features.extend([0, 0])
            
        # Pad or trim to exactly 78 features
        while len(features) < 78:
            features.append(0)
        features = features[:78]
        
        return features
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def process_packet(packet):
    """Process individual packet and update flow"""
    try:
        flow_key = get_flow_key(packet)
        if not flow_key:
            return None
            
        current_time = time.time()
        
        # Initialize flow if new
        if flow_key not in flows:
            flows[flow_key]['start_time'] = current_time
            
        flows[flow_key]['last_seen'] = current_time
        
        # Determine packet direction (simplified)
        direction = 'forward'  # You might need more sophisticated logic
        
        # Extract packet info
        packet_info = {
            'length': int(packet.length),
            'timestamp': current_time,
            'direction': direction,
            'tcp': None
        }
        
        # Add TCP info if available
        if hasattr(packet, 'tcp'):
            packet_info['tcp'] = {
                'flags_psh': getattr(packet.tcp, 'flags_push', 0),
                'flags_urg': getattr(packet.tcp, 'flags_urg', 0),
                'flags_fin': getattr(packet.tcp, 'flags_fin', 0),
                'flags_syn': getattr(packet.tcp, 'flags_syn', 0),
                'flags_rst': getattr(packet.tcp, 'flags_reset', 0),
                'flags_ack': getattr(packet.tcp, 'flags_ack', 0),
                'hdr_len': getattr(packet.tcp, 'hdr_len', 0),
            }
            
        flows[flow_key]['packets'].append(packet_info)
        
        # Clean old flows (keep only recent ones)
        if len(flows[flow_key]['packets']) > 100:
            flows[flow_key]['packets'] = flows[flow_key]['packets'][-50:]
            
        return flow_key
        
    except Exception as e:
        print(f"Error processing packet: {e}")
        return None

def cleanup_old_flows():
    """Remove flows that haven't been seen recently"""
    current_time = time.time()
    old_flows = [k for k, v in flows.items() 
                 if current_time - v['last_seen'] > 300]  # 5 minutes
    for flow_key in old_flows:
        del flows[flow_key]

print("----- Starting live intrusion detection... -----")
print("Collecting packets to build flows...")

packet_count = 0
last_cleanup = time.time()

try:
    for packet in capture.sniff_continuously():
        packet_count += 1
        
        flow_key = process_packet(packet)
        
        if flow_key and len(flows[flow_key]['packets']) >= 10:  # Analyze after 10 packets
            features = extract_flow_features(flows[flow_key])
            
            if features and len(features) == 78:
                try:
                    features_array = np.array(features).reshape(1, -1)
                    prediction = model.predict(features_array)[0]
                    probability = model.predict_proba(features_array)[0]

                    label = "🚨 MALICIOUS" if prediction == 1 else "✅ NORMAL"
                    confidence = max(probability) * 100

                    print(f"[{time.strftime('%H:%M:%S')}] {label} "f"(Confidence: {confidence:.1f}%) - Flow: {flow_key[:50]}...")

                except Exception as e:
                    print(f"⚠️ Error during prediction: {str(e)}")
            else:
                print(f"⚠️ Skipping flow (unexpected number of features: {len(features)})")

        
        # Periodic cleanup
        if time.time() - last_cleanup > 60:  # Every minute
            cleanup_old_flows()
            last_cleanup = time.time()
            print(f"Active flows: {len(flows)}")
        
        if packet_count % 100 == 0:
            print(f"Processed {packet_count} packets, tracking {len(flows)} flows")
            
except KeyboardInterrupt:
    print("\n----- Stopping capture -----")
    print(f"Total packets processed: {packet_count}")
    print(f"Active flows: {len(flows)}")