import socket
from struct import pack, unpack_from
import csv
from id_manager import (
    devices,
    vendors
)


def discover():
    """
    Discover devices on the network, similar to the RSLinx
    Ethernet I/P driver
    """
    devices = []
    request = _build_list_identity()

    # get available ip addresses
    # returns a tuple of ipconfig
    addresses = socket.getaddrinfo(socket.gethostname(), None)

    # we're going to send a request for all available ipv4
    # addresses and build a list of all the devices that reply
    for ip in addresses:
        # IP version 4 (IPv4) is often represented by the number 2
        if ip[0] == 2:
            # create a socket
            # Creates a UDP (User Datagram Protocol) (SOCK_DGRAM) socket
            #  using the IPv4 (AF_INET) address family.
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            # Enables broadcasting to allow messages to be sent
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Binds a port to the IP address string in the tuple.
            s.bind((ip[4][0], 0))
            # Sends request data to all devices on port 44818.
            s.sendto(request, ('255.255.255.255', 44818))
            try:
                while True:
                    # Receive data in 4096 byte chunks
                    ret = s.recv(4096)
                    # <Q, 64-bit integer;
                    #  From the first position in the tuple, [0],
                    #  read in 14 bytes from the beginning.
                    context = unpack_from('<Q', ret, 14)[0]
                    # Mystery hex
                    if context == 0x006d6f4d6948:
                        devices.append(parse(ret))
            except Exception:
                pass
            try:
                s.close()
                print(f'Read: {ip[4][0]}')
            except (Exception,):
                pass

    write_csv(devices)


def write_csv(data):
    csv_file_path = './devices.csv'

    with open(csv_file_path, 'w', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=data[0].keys())
        csv_writer.writeheader()
        csv_writer.writerows(data)


def _build_list_identity():
    """
    Build the list identity request for discovering Ethernet I/P
    devices on the network
    """
    cip_service = 0x63
    cip_length = 0x00
    cip_session_handle = 0x0000
    cip_status = 0x00
    cip_response = 0xFA
    cip_context1 = 0x6948
    cip_context2 = 0x6f4d
    cip_context3 = 0x006d
    cip_options = 0x00

    # <,  indicates little-endian byte order (least significant byte first)
    #  H, Unsigned short integer (2 bytes)
    #  I, Unsigned integer (4 bytes)
    return pack("<HHIIHHHHI",
                cip_service,
                cip_length,
                cip_session_handle,
                cip_status,
                cip_response,
                cip_context1,
                cip_context2,
                cip_context3,
                cip_options)


def parse(data, ip_address=None):
    Length = unpack_from('<H', data, 28)[0]
    EncapsulationVersion = unpack_from('<H', data, 30)[0]

    long_ip = unpack_from('<I', data, 36)[0]
    if ip_address:
        IPAddress = ip_address
    else:
        IPAddress = socket.inet_ntoa(pack('<L', long_ip))

    VendorID = unpack_from('<H', data, 48)[0]
    if VendorID in vendors.keys():
        Vendor = vendors[VendorID]
    else:
        Vendor = "Unknown"

    DeviceID = unpack_from('<H', data, 50)[0]
    if DeviceID in devices.keys():
        DeviceType = devices[DeviceID]
    else:
        DeviceType = "Unknown"

    ProductCode = unpack_from('<H', data, 52)[0]
    major = unpack_from('<B', data, 54)[0]
    minor = unpack_from('<B', data, 55)[0]
    Revision = str(major) + '.' + str(minor)

    Status = unpack_from('<H', data, 56)[0]
    SerialNumber = hex(unpack_from('<I', data, 58)[0])
    ProductNameLength = unpack_from('<B', data, 62)[0]
    ProductName = str(data[63:63+ProductNameLength].decode('utf-8'))

    state = data[-1:]
    State = unpack_from('<B', state, 0)[0]

    return {
        'ProductName': ProductName,
        'IPAddress': IPAddress,
        'Vendor': Vendor,
        'DeviceType': DeviceType,
        'Length': Length,
        'EncapsulationVersion': EncapsulationVersion,
        'ProductCode': ProductCode,
        'Revision': Revision,
        'Status': Status,
        'SerialNumber': SerialNumber,
        'ProductNameLength': ProductNameLength,
        'State': State
    }


discover()
