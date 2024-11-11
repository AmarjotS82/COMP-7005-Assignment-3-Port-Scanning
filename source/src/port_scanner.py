from scapy.all import IP, TCP, ICMP, sr1
import argparse
import sys
import time 
from concurrent.futures import ThreadPoolExecutor,  as_completed


def create_packet(target_IP_Addr, target_port_num):
    source_port = 3000
    ip_packet = IP(dst=target_IP_Addr)
    tcp_packet = TCP(sport=source_port, dport=target_port_num,flags='S')
    layered_packet = ip_packet / tcp_packet
    return layered_packet

def get_port_status(packet_flags, port_num):
    status = ""
    if packet_flags == "SA":
        status = "open"
    elif packet_flags == "RA":
        status = "closed"
    print("Port " + str(port_num) + " is " + status + "\n")

def send_crafted_packet(packet, port_num, start_port_num, delay):
    print(f"\rScanning port {port_num}...\n", end='')
    if(port_num > start_port_num and delay > 0):
            time.sleep(delay)
    response = sr1(packet, timeout=3, verbose= False)
    return response
    

def scan_ports(target_IP_addr, start_port_num, end_port_num, delay):
    print("Scanning device with IP address: " + str(target_IP_addr) + " starting from port "  + str(start_port_num) + " to port " + str(end_port_num) + " with a delay of " + str(delay) + " seconds")
    max_threads = 15
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        threads = {}
        for port_num in range(start_port_num, end_port_num + 1):
            packet = create_packet(target_IP_addr, port_num)
            thread = executor.submit(send_crafted_packet,packet, port_num, start_port_num, delay)
            threads[thread] = port_num

        for thread in as_completed(threads):
            port_num = threads[thread]
            try:
                result = thread.result()
                if(result):
                    tcp_layer = result[TCP]
                    flags = tcp_layer.flags
                    str_rep_flags = str(flags)
                    get_port_status(str_rep_flags, port_num)
                else:
                    print(f"Port {port_num} is filtered" + "\n")
            except Exception as e:
                print(f"Error scanning port {port_num}: {e}")

def ping_device(target_IP_Addr):
    ping_packet = IP(dst=target_IP_Addr) / ICMP()
    response = sr1(ping_packet, timeout=2, verbose=False)
    if not response:
        sys.exit("Error: device  is unreachable! Check that IP address it correct") 

def parse_arguments():
    starting_port = 1
    end_port = 65535
    delay_milliseconds = 0
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument("target_IP_Address",type=str, help="The IP address of the target device that will be scanned")
    parser.add_argument("--start",type=int, default=starting_port, help="The port number to start scanning from (ranges from 1 to 65535)")
    parser.add_argument("--end",type=int, default=end_port, help="The port number to end the scanning at (ranges from 1 to 65535)")
    parser.add_argument("--delay",type=int, default=delay_milliseconds, help="The delay between scans in milliseconds")
    parser.print_help()
    print("\n")
    args = parser.parse_args()
    return args
    
def validate_args(arguments):
    number_chunks_in_ip = arguments.target_IP_Address.split(".")

    if(len(number_chunks_in_ip) != 4 ):
        sys.exit("Error: Invalid IP address not enough dots should be 4!")
    
    for number in number_chunks_in_ip:

        if number.isalpha():
            sys.exit("Error: Invalid IP address contains a letter!")
        try:
            int(number)
        except:
            sys.exit("Error: Invalid IP address contains a character that isn't a number!")
        if int(number) > 255 or int(number) < 0:
            sys.exit("Error: Invalid IP address contains a number outside of te range of 0 to 255")

    ping_device(arguments.target_IP_Address)
    arg_arr = [arguments.start, arguments.end ]
    port_label = ""
    for cmd_arg in arg_arr:
        if(cmd_arg == arguments.start):
            port_label = "starting"
        else:
            port_label = "ending"
        if cmd_arg < 1:
            sys.exit("Error: Invalid " + port_label + " port number! Port numbers start from 1!")  
        elif cmd_arg > 65535:
            sys.exit("Error: Invalid " + port_label + " port number outside range of 1 to 65535")
    if  arguments.end  < arguments.start:
        sys.exit("Error: Invalid end port number! It must be greater than the starting port number")

    if arguments.delay < 0:
        sys.exit("Error: Invalid delay can't be less than zero!")
    return arguments

def main():
    args = parse_arguments()
    validated_args = validate_args(args)
    delay_in_seconds = validated_args.delay / 1000
    scan_ports(validated_args.target_IP_Address, validated_args.start, validated_args.end, delay_in_seconds)         
main()

