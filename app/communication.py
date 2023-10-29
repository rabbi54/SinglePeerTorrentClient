import struct
import random
import ipaddress
import math
import socket
import requests
from app.const import SELF_PEER_ID, CHUNK_SIZE
from app.handshake import Handshake
import hashlib


class UDPPkTAnalizer:
    @staticmethod
    def udp_connecting_byte():
        connection_id = 0x41727101980  # default connection id
        action = 0x0  # action (0 = give me a new connection id)
        transaction_id = int(random.randrange(0, 255))
        print("Transaction ID :", transaction_id)
        buffer = struct.pack("!q", connection_id)  # first 8 bytes is connection id
        buffer += struct.pack("!i", action)  # next 4 bytes is action
        buffer += struct.pack("!i", transaction_id)  # next 4 bytes is transaction id

        return buffer, transaction_id

    @staticmethod
    def udp_parse_connection_response(buf, sent_transaction_id):
        print("connecting")
        if len(buf) < 16:
            raise RuntimeError(
                "Wrong response length getting connection id: %s" % len(buf)
            )
        action = struct.unpack_from("!i", buf)[0]  # first 4 bytes is action

        res_transaction_id = struct.unpack_from("!i", buf, 4)[
            0
        ]  # next 4 bytes is transaction id
        if res_transaction_id != sent_transaction_id:
            raise RuntimeError(
                "Transaction ID doesnt match in connection response! Expected %s, got %s"
                % (sent_transaction_id, res_transaction_id)
            )

        if action == 0x0:
            connection_id = struct.unpack_from("!q", buf, 8)[
                0
            ]  # unpack 8 bytes from byte 8, should be the connection_id
            return connection_id
        elif action == 0x3:
            error = struct.unpack_from("!s", buf, 8)
            raise RuntimeError(
                "Error while trying to get a connection response: %s" % error
            )

    @staticmethod
    def udp_announcing_byte(con_id, torrent):
        action = 0x1
        trx_id = int(random.randrange(0, 255))
        buffer = struct.pack("!q", con_id)  # first 8 bytes is connection id
        buffer += struct.pack("!i", action)  # next 4 bytes is action
        buffer += struct.pack("!i", trx_id)  # next 4 bytes is transaction id
        buffer += torrent.info_hash_raw  # info hash
        buffer += SELF_PEER_ID  # peer id
        buffer += struct.pack("!q", 0)  # downloaded
        buffer += struct.pack("!q", torrent.info.length)  # left
        buffer += struct.pack("!q", 0)  # uploaded
        buffer += struct.pack("!i", 0)  # event 0, 1, 2, 3
        buffer += struct.pack("!i", 0)  # ip
        buffer += struct.pack("!i", int(random.randrange(0, 244)))  # key
        buffer += struct.pack("!i", -1)  # max num of peers default -1
        buffer += struct.pack("!H", 6069)  # port
        buffer += struct.pack("!H", 2)  # extension
        return buffer

    @staticmethod
    def udp_parse_announce_response(buf):
        print(len(buf))
        offset = 0
        action = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        trx_id = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        interval = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        leechers = struct.unpack_from("!i", buf, offset)[0]
        offset += 4
        seeders = struct.unpack_from("!i", buf, offset)[0]
        offset += 4

        buf = buf[offset:]
        print(len(buf))
        peers = []
        while len(buf) > 0:
            try:
                ip_addr = str(ipaddress.ip_address(struct.unpack_from("!I", buf, 0)[0]))
                peers.append(f"{ip_addr}:{struct.unpack_from('!H', buf, 4)[0]}")
            except:
                print(f"Unable to parse ip {struct.unpack_from('!I', buf, 0)[0]}")
            buf = buf[6:]

        return peers

    @staticmethod
    def get_udp_ip_port(url):
        hostname = url.split("//", 1)[1].split(":", 1)[0]
        ip = url.split("//", 1)[1].split(":", 1)[1].split("/")[0]
        return socket.gethostbyname(hostname), int(ip)


class UDPTrackerRequester:
    def __init__(self, torrent) -> None:
        self.torrent = torrent

    def create_udp_socket(self, time_out):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(time_out)
        return sock

    def perform_connecting(self, sock, url):
        self.connection = UDPPkTAnalizer.get_udp_ip_port(url)
        request, transaction_id = UDPPkTAnalizer.udp_connecting_byte()
        sock.sendto(request, self.connection)
        buffer = sock.recvfrom(1048)[0]
        conn_id = UDPPkTAnalizer.udp_parse_connection_response(buffer, transaction_id)
        print(conn_id)
        return conn_id

    def get_peers(self, url):
        sock = self.create_udp_socket(5)
        conn_id = self.perform_connecting(sock, url)
        sock.sendto(
            UDPPkTAnalizer.udp_announcing_byte(conn_id, self.torrent), self.connection
        )
        buffer = sock.recvfrom(4192)[0]
        peers = UDPPkTAnalizer.udp_parse_announce_response(buffer)
        return peers


class HTTPTrackerRequest:
    def __init__(self, torrent) -> None:
        self.torrent = torrent
        pass

    def __generate_payload_for_trackers(self):
        # print(encode_bencode(info['info_hash']))
        payload = {
            "info_hash": self.torrent.info_hash_raw,
            "peer_id": SELF_PEER_ID,
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": self.torrent.info.piece_length,
        }
        return payload

    def request_tracker(self):
        payload = self.__generate_payload_for_trackers()
        url = self.torrent.announce
        return requests.get(url, payload)


class FileDownloader:
    def __init__(self, torrent) -> None:
        self.torrent = torrent

    def handshake_peer(self, ip, port):
        info_hash = self.torrent.info_hash_raw
        handshake = Handshake(info_hash=info_hash, peer_id=SELF_PEER_ID)
        incoming_handshake, _ = self.connect_for_handshaking(ip, port, handshake)
        print("Peer ID:", incoming_handshake.peer_id.hex())

    def connect_for_handshaking(self, ip, port, handshake):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.settimeout(30)
            self.sock.connect((ip, int(port)))
            self.sock.sendall(handshake.__bytes__())
            received_handshake = self.sock.recv(len(handshake.__bytes__()))
            incoming_handshake = Handshake.from_bytes(received_handshake)
            return incoming_handshake, self.sock
        except Exception as e:
            print(f"Connection failed {e}")
            return None, self.sock

    def wait_for_unchoke(self):
        # we must wait for the unchoke message
        length, msg_type = self.sock.recv(4), self.sock.recv(1)
        while msg_type != b"\x01":  # wait for unchoke
            length, msg_type = self.sock.recv(4), self.sock.recv(1)

    def request_for_piece(self, length):
        self.sock.recv(int.from_bytes(length, byteorder="big") - 1)  # read the bitfield
        self.sock.sendall(b"\x00\x00\x00\x01\x02")  # 1 length, 2 type (interested)
        self.wait_for_unchoke()

    def download_single_piece(self, piece_index, output_file, length):
        self.request_for_piece(length)
        piece = self.download_a_piece(piece_index)
        with open(output_file, "wb") as f:
            f.write(piece)

    def is_last_piece(self, piece_index):
        return piece_index == (len(self.torrent.info.pieces) // 20) - 1

    def get_piece_length(self, piece_index):
        piece_length = self.torrent.info.piece_length
        if self.is_last_piece(piece_index):
            piece_length = self.torrent.info.length % piece_length
        return piece_length

    def request_for_chunk(self, piece_index, piece_length, i):
        msg_id = b"\x06"
        chunk_index = piece_index.to_bytes(4)
        chunk_begin = (i * CHUNK_SIZE).to_bytes(4)
        # if this is the last chunk, we need to get the remainder
        if (
            i == math.ceil((piece_length / CHUNK_SIZE)) - 1
            and piece_length % CHUNK_SIZE != 0
        ):
            chunk_length = piece_length % CHUNK_SIZE
        else:
            chunk_length = CHUNK_SIZE
        chunk_length = chunk_length.to_bytes(4)
        print("Requesting", chunk_index, chunk_begin, chunk_length)
        msg = msg_id + chunk_index + chunk_begin + chunk_length
        msg = len(msg).to_bytes(4) + msg
        self.sock.sendall(msg)
        return chunk_length

    def receive_a_block(self, chunk_length):
        # wait for the piece
        length, msg_type = int.from_bytes(self.sock.recv(4)), self.sock.recv(1)
        # assert msg_type == b"\x07"
        # now we are getting the payload
        resp_index = int.from_bytes(self.sock.recv(4))
        resp_begin = int.from_bytes(self.sock.recv(4))

        block = b""
        to_get = int.from_bytes(chunk_length)
        while len(block) < to_get:
            block += self.sock.recv(to_get - len(block))
        return block

    def download_a_piece(self, piece_index):
        piece_length = self.get_piece_length(piece_index)
        piece = b""
        for i in range(math.ceil(piece_length / CHUNK_SIZE)):
            chunk_length = self.request_for_chunk(piece_index, piece_length, i)
            block = self.receive_a_block(chunk_length)
            piece += block

        og_hash = self.torrent.info.pieces[piece_index * 20 : piece_index * 20 + 20]
        assert hashlib.sha1(piece).digest() == og_hash
        return piece

    def handle_download(self, is_full, output_file, piece_index, peer_index):
        peers = self.torrent.get_peers()
        print(peer_index)
        self.handshake_peer(
            peers[peer_index].split(":")[0], peers[peer_index].split(":")[1]
        )
        print("Waiting for bitfield")
        length, msg_type = self.sock.recv(4), self.sock.recv(1)
        if msg_type != b"\x05":
            raise Exception("Expected bitfield message")
        if is_full:
            self.request_for_piece(length)
            data = b""
            for i in range(len(self.torrent.info.pieces) // 20):
                piece = self.download_a_piece(i)
                data += piece
            with open(output_file, "wb") as f:
                f.write(piece)
                f.write(data)
        else:
            self.download_single_piece(piece_index, output_file, length)
