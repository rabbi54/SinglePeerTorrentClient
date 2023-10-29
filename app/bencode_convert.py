import bencodepy


class Converter:
    def encode_bencode(self, val: any):
        bs_encode = bencodepy.encode(val)
        return bs_encode

    def decode_bencode(self, bencoded_value: bytes):
        val, _ = self._decode(bencoded_value)
        return val

    def _decode(self, bencoded_value: bytes) -> (any, bytes):
        # base:
        if len(bencoded_value) == 0:
            return None, b""
        # handle ints
        if chr(bencoded_value[0]) == "i":
            val = int(bencoded_value.split(b"e")[0][1:])
            remaining = bencoded_value.split(b"e", 1)[1]

            return val, remaining
        # handle strings
        if chr(bencoded_value[0]).isdigit():
            length_str, remaining_after_length = bencoded_value.split(b":", 1)
            length = int(length_str)
            val = remaining_after_length[:length]
            remaining = remaining_after_length[length:]
            return val, remaining
        # handle lists
        if chr(bencoded_value[0]) == "l":
            return self._decode_list(bencoded_value, lst=[])
        if chr(bencoded_value[0]) == "d":
            return self._decode_dict(bencoded_value, dct={})

    def _decode_list(self, bencoded_value: bytes, lst: list) -> (list, bytes):
        bencoded_value = bencoded_value[1:]
        while chr(bencoded_value[0]) != "e":
            val, bencoded_value = self._decode(bencoded_value)
            lst.append(val)
        return lst, bencoded_value[1:]

    def _decode_dict(self, bencoded_value: bytes, dct: dict) -> (dict, bytes):
        bencoded_value = bencoded_value[1:]
        while chr(bencoded_value[0]) != "e":
            key, bencoded_value = self._decode(bencoded_value)
            value, bencoded_value = self._decode(bencoded_value)
            dct[key.decode()] = value
        return dct, bencoded_value[1:]


def bytes_to_str(data):
    try:
        if isinstance(data, bytes):
            return data.decode()
    except UnicodeDecodeError:
        return data.hex()

    raise TypeError(f"Type not serializable: {type(data)}")
