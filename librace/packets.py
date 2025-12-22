import logging
import struct
from librace.constants import RaceId, RaceType
from librace.util import fota_checksum


class RaceHeader:
    """Represents the header of a RACE packet."""

    FORMAT = (
        "<BBHH"  # head (1 byte) + type (1 byte) + length (2 byte) + cmd id (2 byte)
    )
    SIZE = struct.calcsize(FORMAT)

    def __init__(self, head: int, type_: int, id_: int, length: int = 0):
        self.head = head
        self.type = type_
        self.length = length
        self.id = id_

    def pack(self):
        """Serialize the header into bytes."""
        return struct.pack(self.FORMAT, self.head, self.type, self.length, self.id)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into a RaceHeader instance."""
        if len(data) < cls.SIZE:
            raise ValueError("Data too short for RaceHeader")
        head, type_, length, id_ = struct.unpack(cls.FORMAT, data[: cls.SIZE])
        return cls(head, type_, id_, length)

    def __str__(self):
        s = f"head: {self.head}, type: {self.type:#02x}, length: {self.length:#04x}, id: {self.id:#04x}"
        return s


class RacePacket:
    """Represents a full RACE protocol packet, including header and payload."""

    def __init__(self, header: RaceHeader, payload: bytes = b""):
        self.header = header
        self.payload = payload
        self.header.length = len(payload) + 2  # length includes the cmd ID field

    def pack(self):
        """Serialize the packet to bytes."""
        return self.header.pack() + self.payload

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into a RacePacket instance."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        return cls(header, payload)


class ReadFlashPage(RacePacket):
    """Represents a RACE message that reads a flash page."""

    def __init__(self, address: int, size: int = 0x100, storage_type: int = 0):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_STORAGE_PAGE_READ,
        )
        payload = (
            bytes([storage_type]) + bytes([size >> 8]) + struct.pack("<I", address)
        )
        super().__init__(race_header, payload)


class ReadFlashPageResponse(RacePacket):
    """Represents a RACE message that contains a flash page."""

    PREAMBLE_FORMAT = "<BBBBI"  # return_code (1 byte) + storage_type (1 byte) + 0x00 (1 byte) + uninitialised (1 byte) +  read_adress (2 byte)
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(
        self,
        header: RaceHeader,
        return_code: int,
        storage_type: int,
        page_address: int,
        page_data: bytes,
    ):
        self.header = header
        self.page_data = page_data
        self.page_address = page_address
        self.return_code = return_code
        self.storage_type = storage_type
        payload = (
            struct.pack(
                self.PREAMBLE_FORMAT, return_code, storage_type, 0, 0, page_address
            )
            + page_data
        )
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into an instance."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        page_data = payload[cls.PREAMBLE_SIZE : cls.PREAMBLE_SIZE + header.length]
        return_code, storage_type, _, _, page_address = struct.unpack(
            ReadFlashPageResponse.PREAMBLE_FORMAT, payload[:8]
        )
        return cls(header, return_code, storage_type, page_address, page_data)


class ReturnCodeResponse(RacePacket):
    """Represents a RACE response message that just returns a one byte return code."""

    PREAMBLE_FORMAT = "<B"  # return_code (1 byte)
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(self, header: RaceHeader, return_code: int):
        self.header = header
        self.return_code = return_code
        payload = struct.pack(self.PREAMBLE_FORMAT, return_code)
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into an instance."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        return_code = struct.unpack(cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE])[
            0
        ]
        return cls(header, return_code)


class WriteFlashPage(RacePacket):
    """Represents a RACE message that writes a flash page (0x100)."""

    PREAMBLE_FORMAT = "<BB"  # storage_type (1 byte) + num. of pages (1 byte) +
    PAGE_FORMAT = "<BI"  # n * [crc (1 byte) + address (4 bytes) + data]
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(self, start_address: int, data: bytes, storage_type: int = 0):
        if len(data) % 0x100 != 0:
            logging.error(
                f"Length of data must be a multiple of 0x100 (is {hex(len(data))})."
            )
            return None

        num_pages = int(len(data) / 0x100)

        pages = [data[i : i + 0x100] for i in range(0, len(data), 0x100)]
        payload = b""
        for i, page in enumerate(pages):
            checksum = fota_checksum(page)
            address = start_address + (i * 0x100)
            payload += struct.pack(self.PAGE_FORMAT, checksum, address) + page

        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_STORAGE_PAGE_PROGRAM,
        )
        preamble = struct.pack(self.PREAMBLE_FORMAT, storage_type, num_pages)
        payload = preamble + payload
        super().__init__(race_header, payload)


class WriteFlashPageResponse(RacePacket):
    """Writa Flash Page Response"""

    PREAMBLE_FORMAT = "<BBBI"  # return_code? (1 byte) + ??? (1 byte) + num pages? (1 byte) + addr (4 bytes)
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(self, header: RaceHeader, return_code: int, num_pages: int, addr: int):
        self.header = header
        self.return_code = return_code
        self.num_pages = num_pages
        self.addr = addr
        payload = struct.pack(self.PREAMBLE_FORMAT, return_code, 0x00, num_pages, addr)
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        return_code, _, num_pages, addr = struct.unpack(
            cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE]
        )
        return cls(header, return_code, num_pages, addr)


class ErasePartition(RacePacket):
    """Erase FOTA Flash area"""

    PREAMBLE_FORMAT = (
        "<BII"  # storage_type (1 byte) + length (4 bytes) address (4 bytes)
    )
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(self, address: int, length: int, storage_type: int = 0):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_STORAGE_PARTITION_ERASE,
        )
        payload = struct.pack(self.PREAMBLE_FORMAT, storage_type, length, address)
        super().__init__(race_header, payload)


class ErasePartitionReponse(ReturnCodeResponse):
    """Erase FOTA flash area response"""


class FotaPartitionInfoQuery(RacePacket):
    """FOTA Partition Info Query: Request FOTA Start Address"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_PARTITION_INFO_QUERY,
        )
        # ??? (1 byte)
        payload = b"\x00"
        super().__init__(race_header, payload)


class FotaPartitionInfoQueryResponse(RacePacket):
    """FOTA Partition Info Query Response"""

    PREAMBLE_FORMAT = "<BHII"  # return_code (1 byte) + ??? (2 bytes) + fota start address (4 byte) + fota length (4 byte)
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(
        self, header: RaceHeader, return_code: int, start_addr: int, length: int
    ):
        self.header = header
        self.return_code = return_code
        self.start_addr = start_addr
        self.length = length
        payload = struct.pack(
            self.PREAMBLE_FORMAT, return_code, 0x00, start_addr, length
        )
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        return_code, _, start_addr, length = struct.unpack(
            cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE]
        )
        return cls(header, return_code, start_addr, length)


class FotaStart(RacePacket):
    """FOTA Start."""

    def __init__(self):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_START,
        )
        payload = b"\x01\x00"
        super().__init__(race_header, payload)


class FotaStartResponse(ReturnCodeResponse):
    """FOTA Start response with one byte status code"""


class FotaStop(RacePacket):
    """FOTA Stop."""

    def __init__(self):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_STOP,
        )
        payload = b"\x01\x00"
        super().__init__(race_header, payload)


class FotaStopResponse(ReturnCodeResponse):
    """FOTA Stop response with one byte status code"""


class FotaStartTransaction(RacePacket):
    """Start FOTA Transaction"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_START_TRANSCATION,
        )
        payload = b""
        super().__init__(race_header, payload)


class FotaStartTransactionResponse(ReturnCodeResponse):
    """FOTA Start Transaction response with one byte status code"""


class FotaWriteState(RacePacket):
    """FOTA Write State Packet"""

    def __init__(self, state: bytes = b"\x01\x02"):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_WRITE_STATE,
        )
        payload = state
        super().__init__(race_header, payload)


class FotaWriteStateResponse(ReturnCodeResponse):
    """FOTA Write State response with one byte status code"""


class FotaIntegrityCheck(RacePacket):
    """FOTA Integrity Check Packet"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_INTEGRITY_CHECK,
        )
        payload = b"\x01\x00\x00"
        super().__init__(race_header, payload)


class FotaIntegrityCheckResponse(ReturnCodeResponse):
    """FOTA Integrity Check response with one byte status code"""


class FotaCommit(RacePacket):
    """FOTA Integrity Check Packet"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x15,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_FOTA_COMMIT,
        )
        payload = b"\x00"
        super().__init__(race_header, payload)


class FotaCommitResponse(ReturnCodeResponse):
    """FOTA Commit response with one byte status code"""


class GetLinkKey(RacePacket):
    """Represents a RACE message that obtains link keys for bonded Bluetooth devices."""

    def __init__(self):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_GET_LINK_KEY,
        )
        super().__init__(race_header)


class GetLinkKeyResponse(RacePacket):
    """Represents a RACE message that contains link keys for bonded Bluetooth devices."""

    PREAMBLE_FORMAT = (
        "<BBB"  # reserved1 (1 byte) + num_of_devices (1 byte) + reserved2 (1 byte)
    )
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)
    RECORD_SIZE = 6 + 16  # 6 bytes addr + 16 bytes link key
    # NOTE: Devices we have seen so far, don't actually set the bdaddr
    # but leave the bytes unintialised

    def __init__(self, header: RaceHeader, num_of_devices: int, link_keys: list[bytes]):
        self.num_of_devices = num_of_devices
        self.link_keys = link_keys

        # build the payload: count repetitions of (00000000000000 + key)
        records = b"".join([bytes([0x00] * 6) + key for key in link_keys])
        payload = struct.pack(self.PREAMBLE_FORMAT, 0, num_of_devices, 0) + records
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into a GetLinkKeyResponse."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]

        # parse just the count, ignore the two reserved bytes
        _, num_of_devices, _ = struct.unpack(
            cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE]
        )
        records = payload[cls.PREAMBLE_SIZE :]

        link_keys = []
        for i in range(num_of_devices):
            off = i * (cls.RECORD_SIZE + 1)
            # addr = records[off : off + 6][::-1]
            key = records[off + 6 : off + cls.RECORD_SIZE]
            link_keys.append(key)

        return cls(header, num_of_devices, link_keys)


class GetEDRAddress(RacePacket):
    """Represents a RACE message that obtains the device's Bluetooth Address"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_GET_BD_ADDRESS,
        )
        super().__init__(race_header)


class GetEDRAddressResponse(RacePacket):
    """Represents a RACE message that contains the device's Bluetooth Address"""

    PREAMBLE_FORMAT = "<BB"  # return_code (1 byte) + agent_or_partner (1 byte)
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(self, header: RaceHeader, return_code: int, bd_addr: bytes):
        self.header = header
        self.bd_addr = bd_addr
        self.return_code = return_code
        payload = struct.pack(self.PREAMBLE_FORMAT, return_code, 0) + bd_addr
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into an instance."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        # address bytes need to be reversed
        bd_addr = payload[cls.PREAMBLE_SIZE : cls.PREAMBLE_SIZE + header.length][::-1]
        return_code, _ = struct.unpack(
            cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE]
        )
        return cls(header, return_code, bd_addr)


class GetSDKInfo(RacePacket):
    """Represents a RACE message that requests the SDK Info"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_READ_SDK_VERSION,
        )
        super().__init__(race_header)


class BuildVersion(RacePacket):
    """Represents a RACE message that requests the SDK Info"""

    def __init__(self):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_GET_BUILD_VERSION,
        )
        super().__init__(race_header)


class ReadAddress(RacePacket):
    """Represents a RACE message that reads 4 byte from a memory adress."""

    def __init__(self, address: int):
        race_header = RaceHeader(
            head=0x05,
            type_=RaceType.CMD_EXPECTS_RESPONSE,
            id_=RaceId.RACE_READ_ADDRESS,
        )
        payload = b"\x00\x00" + struct.pack("<I", address)
        super().__init__(race_header, payload)


class ReadAddressResponse(RacePacket):
    """Represents a RACE message that contains a read address response."""

    PREAMBLE_FORMAT = (
        "<BHI"  # return_code (1 byte) + 0x00 (2 byte) + read_adress (4 byte)
    )
    PREAMBLE_SIZE = struct.calcsize(PREAMBLE_FORMAT)

    def __init__(
        self, header: RaceHeader, return_code: int, page_address: int, page_data: bytes
    ):
        self.header = header
        self.page_data = page_data
        self.page_address = page_address
        self.return_code = return_code
        payload = (
            struct.pack(self.PREAMBLE_FORMAT, return_code, 0, page_address) + page_data
        )
        super().__init__(header, payload)

    @classmethod
    def unpack(cls, data: bytes):
        """Deserialize bytes into an instance."""
        header = RaceHeader.unpack(data)
        payload = data[RaceHeader.SIZE : RaceHeader.SIZE + header.length]
        page_data = payload[cls.PREAMBLE_SIZE : cls.PREAMBLE_SIZE + header.length]
        return_code, _, page_address = struct.unpack(
            cls.PREAMBLE_FORMAT, payload[: cls.PREAMBLE_SIZE]
        )
        return cls(header, return_code, page_address, page_data)
