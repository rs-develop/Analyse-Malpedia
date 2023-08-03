#!/usr/bin/python
import re
import struct

from datetime import datetime, timezone


def get_metadata_from_path(path, malpedia_path):
    base_addr = 0
    baddr_match = re.search(re.compile("0x(?P<base_addr>[0-9a-fA-F]{8})$"), path)
    if baddr_match:
        base_addr = int(baddr_match.group("base_addr"), 16)

    filename = path.split("/")[-1]

    return {
        "family": get_family_from_path(path),
        "platform": get_family_from_path(path).split(".")[0],
        "filename": filename,
        "base_addr": base_addr,
        "hash": filename.split("_")[0]
    }


def get_family_from_path(path, malpedia_path):
    relative_path = path[len(malpedia_path):]
    relative_path = relative_path.strip("/")
    return relative_path.split("/")[0]


def get_dotnet_families(processed_results):
    if "PEHeaderCheck" not in processed_results:
        return []

    dotnet_families = []
    for result in processed_results["PEHeaderCheck"]:
        family = result["family"]
        if "has_com_descriptor" in result and result["has_com_descriptor"]:
            if not family in dotnet_families:
                dotnet_families.append(family)
    return dotnet_families


def get_word(buffer, start):
    return _get_binary_data(buffer, start, 2)


def get_dword(buffer, start):
    return _get_binary_data(buffer, start, 4)


def get_qword(buffer, start):
    return _get_binary_data(buffer, start, 8)


_unsigned_unpack_formats = {
    2: "H",
    4: "I",
    8: "Q"
}


def get_pe_offset(binary):
    if len(binary) >= 0x40:
        pe_offset = get_word(binary, 0x3c)
        return pe_offset
    raise RuntimeError("Buffer too small to extract PE offset (< 0x40)")


def check_bitness(content):
        bitness = 0
        pe_offset = get_pe_offset(content)
        if pe_offset and len(content) >= pe_offset + 6:
            bitness = get_word(content, pe_offset + 4)
            bitness_map = {0x14c: 32, 0x8664: 64}
            bitness = bitness_map[bitness] if bitness in bitness_map else 0
        return bitness


def check_pe(binary):
    pe_offset = get_pe_offset(binary)
    if pe_offset and len(binary) >= pe_offset + 6:
        bitness = get_word(binary, pe_offset + 4)
        bitness_map = {0x14c: 32, 0x8664: 64}
        return bitness in bitness_map
    return False


def _get_binary_data(buffer, start, length):
    if length not in _unsigned_unpack_formats:
        raise RuntimeError("Unsupported data length")

    try:
        unpacked = struct.unpack(_unsigned_unpack_formats[length], buffer[start:start + length])[0]
    except:
        raise RuntimeError("Unknown error" + str(start) + str(length))
    return unpacked


def get_string(buffer, start_offset):
    string = ""
    current_offset = 0
    current_byte = buffer[start_offset]
    while current_byte != 0 and start_offset + current_offset < len(buffer) - 1:
        string += chr(current_byte)
        current_offset += 1
        current_byte = buffer[start_offset + current_offset]
    return string


def read_unicode_content_from_file(file_path):
    return _read_content_from_file(file_path, "r")


def read_byte_content_from_file(file_path):
    return _read_content_from_file(file_path, "rb")


def _read_content_from_file(file_path, mode):
    with open(file_path, mode) as file_handle:
        return file_handle.read()


def write_unicode_content_to_file(data, file_path):
    return _write_content_to_file(data, file_path, "w")


def write_byte_content_to_file(data, file_path):
    return _write_content_to_file(data, file_path, "wb")


def _write_content_to_file(data, file_path, mode):
    with open(file_path, mode) as file_handle:
        return file_handle.write(data)


def convertUnixTimestamp(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def convertStrTimestampToUnix(timestamp):
    return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')


def getDateObjectFromTimestamp(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)

def getCurrentYear():
    return datetime.now().year


class CompareResult:
    COMPARE_NOT_POSSIBLE = -1
    COMPARE_TRUE = 1
    COMPARE_FALSE = 0