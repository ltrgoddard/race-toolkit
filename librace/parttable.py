import struct


def parse_partition_table(data: bytes):
    offset = 0x0C
    entry_size = 48
    partitions = []
    ptype = 0

    while ptype != 255:
        entry = data[offset : offset + entry_size]

        (address,) = struct.unpack_from("<I", entry, 0)  # Little-endian uint32
        (length,) = struct.unpack_from("<I", entry, 8)  # After 4 bytes of 0s
        ptype = entry[36]

        if address == 0xFFFFFFFF and length == 0xFFFFFFFF:
            break  # Assume no more valid entries

        partitions.append((address, length, ptype))

        offset += entry_size

    return partitions
