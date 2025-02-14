from iputils import *
import struct
import socket

#Constantes do ICMP
ICMP_PROTO = 0x01
ICMP_TIME_EXCEEDED = 11  

tabela_encaminhamento = {}

def calculate_checksum(header):
    if len(header) % 2 != 0:
        header += b'\x00' 
    checksum = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
            src_addr, dst_addr, payload = read_ipv4_header(datagrama)

        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            if ttl <= 1:
                self._send_icmp_time_exceeded(src_addr, dst_addr, datagrama)
                return

            ttl -= 1

            header = datagrama[:20]
            header = bytearray(header)
            header[8] = ttl

            header[10:12] = b'\x00\x00'  
            checksum = calculate_checksum(bytes(header))
            header[10:12] = checksum.to_bytes(2, byteorder='big')

            datagrama = bytes(header) + datagrama[20:]

            next_hop = self._next_hop(dst_addr)
            if next_hop:
                self.enlace.enviar(datagrama, next_hop)

    def _send_icmp_time_exceeded(self, src_addr, dst_addr, original_datagrama):
        VERSION_IHL = (4 << 4) | 5
        DSCP_ECN = 0
        TOTAL_LENGTH = 20 + 8 + 28
        IDENTIFICATION = 0
        FLAGS_FRAGMENTOFFSET = 0
        TTL = 64  
        PROT = ICMP_PROTO 
        CHECKSUM = 0  
        SRC_ADDR = socket.inet_aton(self.meu_endereco)
        DEST_ADDR = socket.inet_aton(src_addr)  

        icmp_type = ICMP_TIME_EXCEEDED  
        icmp_code = 0
        icmp_checksum = 0
        icmp_unused = 0  
        icmp_payload = original_datagrama[:28]

        icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, icmp_unused)
        icmp_packet = icmp_header + icmp_payload

        icmp_checksum = calculate_checksum(icmp_packet)
        icmp_header = struct.pack('!BBHI', icmp_type, icmp_code, icmp_checksum, icmp_unused)
        icmp_packet = icmp_header + icmp_payload

        header_without_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            VERSION_IHL,
            DSCP_ECN,
            TOTAL_LENGTH,
            IDENTIFICATION,
            FLAGS_FRAGMENTOFFSET,
            TTL,
            PROT,
            CHECKSUM,
            SRC_ADDR,
            DEST_ADDR
        )

        CHECKSUM = calculate_checksum(header_without_checksum)

        icmp_datagrama = struct.pack(
            '!BBHHHBBH4s4s',
            VERSION_IHL,
            DSCP_ECN,
            TOTAL_LENGTH,
            IDENTIFICATION,
            FLAGS_FRAGMENTOFFSET,
            TTL,
            PROT,
            CHECKSUM,
            SRC_ADDR,
            DEST_ADDR
        ) + icmp_packet

        next_hop = self._next_hop(src_addr)
        if next_hop:
            self.enlace.enviar(icmp_datagrama, next_hop)


    def _next_hop(self, dest_addr):
        dest_num = int(dest_addr.split('.')[3]) | int(dest_addr.split('.')[2]) << 8 | \
                int(dest_addr.split('.')[1]) << 16 | int(dest_addr.split('.')[0]) << 24

        for cidr, next_hop in self.tabela_encaminhamento:
            ip, prefix_len = cidr.split('/')
            prefix_len = int(prefix_len)

            ip_num = int(ip.split('.')[3]) | int(ip.split('.')[2]) << 8 | \
                    int(ip.split('.')[1]) << 16 | int(ip.split('.')[0]) << 24

            mask = (1 << (32 - prefix_len)) - 1
            mask = ~mask

            if (dest_num & mask) == (ip_num & mask):
                return next_hop

        # Caso padrão (rota padrão)
        if '0.0.0.0/0' in self.tabela_encaminhamento:
            return self.tabela_encaminhamento['0.0.0.0/0']

        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        self.tabela_encaminhamento = sorted(
            tabela, 
            key=lambda x: int(x[0].split('/')[1]), 
            reverse=True
        )


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        VERSION_IHL = (4 << 4) | 5
        DSCP_ECN = 0
        TOTAL_LENGTH = 20 + len(segmento)
        IDENTIFICATION = 1234 #MELHORAR ISSO POIS NAO SEI AO CERTO
        FLAGS_FRAGMENTOFFSET = (0b000 << 13)
        TTL = 64
        PROT = 0x06
        CHECKSUM = 0x00 #ver isso aqui pelo amor de deus
        SRC_ADDR = socket.inet_aton(self.meu_endereco)
        DEST_ADDR = socket.inet_aton(dest_addr)
        OPTIONS = b''

        header_without_checksum = struct.pack(
            '!BBHHHBBH4s4s',
            VERSION_IHL,
            DSCP_ECN,
            TOTAL_LENGTH,
            IDENTIFICATION,
            FLAGS_FRAGMENTOFFSET,
            TTL,
            PROT,
            CHECKSUM,
            SRC_ADDR,
            DEST_ADDR
        )

        CHECKSUM = calculate_checksum(header_without_checksum)

        datagrama = struct.pack(
            '!BBHHHBBH4s4s',
            VERSION_IHL,
            DSCP_ECN,
            TOTAL_LENGTH,
            IDENTIFICATION,
            FLAGS_FRAGMENTOFFSET,
            TTL,
            PROT,
            CHECKSUM,
            SRC_ADDR,
            DEST_ADDR
        ) + segmento


        self.enlace.enviar(datagrama, next_hop)
