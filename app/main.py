import json
import sys
from app.torrent import Torrent
from app.communication import FileDownloader
from app.bencode_convert import Converter, bytes_to_str


def handle_info_commad():
    torrent = Torrent(sys.argv[2])
    print(f"Tracker URL: {torrent.announce}")
    print(f"Length : {torrent.info.length}")
    print(f"Info Hash: {torrent.info_hash}")
    print(f"Piece Length: {torrent.info.piece_length}")
    print("Piece Hashes:")
    for p in torrent.info.pieces_hash:
        print(p)


def handle_peers_command():
    torrent = Torrent(sys.argv[2])
    peers = print(torrent.get_peers())
    return peers


def handle_download_command(is_full):
    output_file = sys.argv[3]
    torrent_file = sys.argv[4]
    piece_index = None
    if not is_full:
        piece_index = int(sys.argv[5])
        peer_index = int(sys.argv[6])
    else:
        peer_index = int(sys.argv[5])
    torrent = Torrent(torrent_file)
    file_downloader = FileDownloader(torrent)
    file_downloader.handle_download(is_full, output_file, piece_index, peer_index)
    print(f"Download test.torrent to {output_file}")


def handle_handshake_command():
    ip_addr = sys.argv[3]
    ip, port = ip_addr.split(":")

    file_name = sys.argv[2]
    torrent = Torrent(file_name)
    file_downloader = FileDownloader(torrent)
    file_downloader.handshake_peer(ip, port)


def main():
    command = sys.argv[1]
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoder = Converter()
        print(json.dumps(decoder.decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        handle_info_commad()
    elif command == "peers":
        handle_peers_command()
    elif command == "handshake":
        handle_handshake_command()
    elif command == "download_piece":
        handle_download_command(False)
    elif command == "download":
        handle_download_command(True)
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
