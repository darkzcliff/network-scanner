import nmap
import socket
from scapy.all import sniff, IP
from scapy.layers.http import HTTPRequest 

def my_ip():
    def get_ip():
        sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sc.connect(("8.8.8.8", 80))
        addr = (sc.getsockname()[0])
        sc.close()
        return addr
    return get_ip()

def net_scanner():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/27', arguments='-sn')
    
    active_hosts = []
    scanned_host = []
    
    host_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]

    for host, status in host_list:
        if status != 'down':
            active_hosts.append(host)
            
    for ip in active_hosts:
        detail_hosts = {
            'ip': ip,
            'desc': ''
        }

        if ip == my_ip():
            detail_hosts['desc'] = 'You'
        else:
            detail_hosts['desc'] = ''

        scanned_host.append(detail_hosts)

    print("Connected Host: ")
    for target in scanned_host:
        print(f"IP: {target['ip']}\t{target['desc']}")

def get_packet(pkg):
    if pkg.haslayer(HTTPRequest):
        data = pkg[HTTPRequest]
        accessed = f"{pkg[IP].src} accessed {data.Host.decode()}{data.Path.decode()}"
        print(accessed)


if __name__ == '__main__':
    set_iface = "wlp1s0"
    filter_by = ""

    net_scanner()

    print("\nMonitoring: ")
    sniff(iface=set_iface, prn=get_packet, filter=filter_by)
