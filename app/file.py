from app.bencode_convert import Converter


class File:
    def __init__(self, file_name) -> None:
        self.file_name = file_name
        pass

    def get_file_content(self):
        try:
            file = open(self.file_name, "rb")
            return file.read()
        except FileNotFoundError:
            print("File not found")

    def get_torrent_file_content(self):
        content = self.get_file_content()
        converter = Converter()
        torrent_dict = converter.decode_bencode(content)
        return torrent_dict
