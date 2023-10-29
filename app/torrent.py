from dataclasses import dataclass, field
from app.file import File
from typing import List
import hashlib
from app.bencode_convert import Converter
from app.communication import UDPTrackerRequester, HTTPTrackerRequest


@dataclass
class InfoFiles:
    length: int
    path: List[str]


@dataclass
class TorrentInfo:
    piece_length: int
    pieces: str
    name: str
    length: int
    files: List[InfoFiles]
    pieces_hash: list = field(init=False)

    def __post_init__(self):
        self.pieces_hash = [
            self.pieces[x : x + 20].hex() for x in range(0, len(self.pieces), 20)
        ]


class Torrent:
    def dataclass_from_dict(self, klass, dikt):
        try:
            fieldtypes = klass.__annotations__  # this can be also simplified I believe
            return klass(
                **{f: self.dataclass_from_dict(fieldtypes[f], dikt[f]) for f in dikt}
            )
        except Exception:
            if isinstance(dikt, (tuple, list)):
                return [self.dataclass_from_dict(klass.__args__[0], f) for f in dikt]
            return dikt

    def get_info_hash(self):
        encoded_info = Converter().encode_bencode(self.info_dict)
        sha1 = hashlib.sha1(encoded_info)
        return sha1.hexdigest()

    def get_info_hash_raw(self):
        encoded_info = Converter().encode_bencode(self.info_dict)
        sha1 = hashlib.sha1(encoded_info)
        return sha1.digest()

    def get_peers_addr(self, response_dict: dict):
        peers = response_dict["peers"]
        peers_addr_list = list(map(lambda e: f"{e['ip'].decode()}:{e['port']}", peers))
        return peers_addr_list

    def get_peers(self):
        scheme = self.announce.split(":", 1)[0]
        if scheme == "http":
            response = HTTPTrackerRequest(self).request_tracker()
            reponse_dict = Converter().decode_bencode(response.content)
            peers = self.get_peers_addr(reponse_dict)

        elif scheme == "udp":
            peers = UDPTrackerRequester(self).get_peers(self.announce)
            # print(peers)
        return peers

    def __init__(self, torrent_file):
        file = File(torrent_file)
        torrent_file_content = file.get_torrent_file_content()
        torrent_info_dict = torrent_file_content.get("info")

        self.announce = torrent_file_content.get("announce").decode()
        self.announce_list = torrent_file_content.get("announce-list")
        self.creation_date = torrent_file_content.get("creation date")
        self.comment = torrent_file_content.get("comment")
        self.created_by = torrent_file_content.get("comment")
        self.info_dict = torrent_info_dict
        self.info = TorrentInfo(
            torrent_info_dict.get("piece length"),
            torrent_info_dict.get("pieces"),
            torrent_file_content.get("name"),
            torrent_info_dict.get("length"),
            self.dataclass_from_dict(InfoFiles, torrent_file_content.get("files")),
        )

        self.info_hash = self.get_info_hash()
        self.info_hash_raw = self.get_info_hash_raw()
