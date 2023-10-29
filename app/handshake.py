class Handshake:
    req = b"\x13"
    req += b"BitTorrent protocol"

    # The optional bits, note that normally some of these are set by most clients
    req += b"\x00\x00\x00\x00\x00\x00\x00\x00"

    header = req

    def __init__(self, info_hash, peer_id) -> None:
        self.info_hash = info_hash
        self.peer_id = peer_id

    def __bytes__(self):
        byte = self.header + self.info_hash + self.peer_id
        return byte

    @classmethod
    def parse(cls, data: bytes):
        data = data[len(cls.header) :]
        info_hash = data[:20]
        peer_id = data[20:40]
        return cls(info_hash, peer_id)

    @classmethod
    def from_bytes(cls, bytes: bytes):
        # Using just [0] returns an int, use [0:1] to get a bytes object
        pstrlen = bytes[0:1]
        if pstrlen != b"\x13":
            raise ValueError(f"pstrlen must be 19, got {repr(pstrlen)}")
        pstr = bytes[1:20]
        if pstr != b"BitTorrent protocol":
            raise ValueError(f"pstr must be b'BitTorrent protocol', got {pstr}")
        info_hash = bytes[28:48]
        peer_id = bytes[48:68]

        return cls(info_hash, peer_id)
