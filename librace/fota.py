import logging
import math
import os

from tqdm import tqdm

from librace.constants import RaceId, RaceType
from librace.packets import (
    ErasePartition,
    ErasePartitionReponse,
    FotaCommit,
    FotaIntegrityCheck,
    FotaIntegrityCheckResponse,
    FotaStart,
    FotaStartResponse,
    FotaStartTransaction,
    FotaStartTransactionResponse,
    FotaWriteState,
    FotaWriteStateResponse,
    RaceHeader,
    RacePacket,
    FotaPartitionInfoQuery,
    FotaPartitionInfoQueryResponse,
    WriteFlashPage,
    WriteFlashPageResponse,
)
from librace.race import RACE

from bumble.colors import color


class FOTAUpdater:
    """
    FOTAUpdater will execute a full FOTA update with a given update file. Only works for non-TWS headphones.
    """

    CHUNK_SIZE = 0x100

    def __init__(self, r: RACE, chunks_per_write: int):
        self.r = r
        self.fota_partition_addr = None
        self.fota_partition_length = None
        self.fota_start = False
        self.fota_success = False
        self.fota_partition_erased = False
        self.fota_integrity_check = False
        self.chunks_per_write = chunks_per_write

    async def send_sync(self, race_packet: RacePacket):
        await self.r.send_sync(race_packet)

    def recv(self, data: bytes):
        race_header = RaceHeader.unpack(data[: RaceHeader.SIZE])

        if race_header.type == RaceType.RESPONSE:
            if race_header.id == RaceId.RACE_FOTA_PARTITION_INFO_QUERY:
                packet = FotaPartitionInfoQueryResponse.unpack(data)
                logging.info(
                    f"Received Partition Query response. Start FOTA at {hex(packet.start_addr)}"
                )
                self.fota_partition_addr = packet.start_addr
                self.fota_partition_length = packet.length
            elif race_header.id == RaceId.RACE_FOTA_START_TRANSCATION:
                packet = FotaStartTransactionResponse.unpack(data)
                logging.debug(
                    f"Received FOTA Start Transaction response. Status: {packet.return_code}"
                )
            elif race_header.id == RaceId.RACE_FOTA_WRITE_STATE:
                packet = FotaWriteStateResponse.unpack(data)
                logging.debug(
                    f"Received FOTA Write State response. Status: {packet.return_code}"
                )
            elif race_header.id == RaceId.RACE_FOTA_START:
                packet = FotaStartResponse.unpack(data)
                logging.debug(
                    f"Received FOTA Start response. Status: {packet.return_code}."
                )
                self.fota_start = True
            elif race_header.id == RaceId.RACE_STORAGE_PAGE_PROGRAM:
                packet = WriteFlashPageResponse.unpack(data)
                logging.debug(
                    f"Received Page Program response. Status: {packet.return_code}."
                )
                if packet.return_code == 0x0A:
                    logging.info(f"Checksum error at {packet.addr}")
                self.fota_success = True if packet.return_code == 0 else False
            elif race_header.id == RaceId.RACE_STORAGE_PARTITION_ERASE:
                packet = ErasePartitionReponse.unpack(data)
                logging.debug(
                    f"Received Partition Erase response. Status: {packet.return_code}."
                )
                self.fota_partition_erased = True if packet.return_code == 0 else False
            elif race_header.id == RaceId.RACE_FOTA_INTEGRITY_CHECK:
                packet = FotaIntegrityCheckResponse.unpack(data)
                logging.debug(
                    f"Received Integrity Check response. Status: {packet.return_code}."
                )
                self.fota_integrity_check = True if packet.return_code == 0 else False
            else:
                if race_header.id in RaceId:
                    logging.debug(
                        f"Received {RaceId(race_header.id)._name_} response ({data.hex()})"
                    )
                else:
                    logging.info(
                        f"Received unknown RACE response with ID: {hex(race_header.id)}"
                    )
        elif race_header.type == RaceType.CMD_EXPECTS_RESPONSE:
            if race_header.id == RaceId.RACE_FOTA_STOP:
                logging.error(
                    f"Received FOTA Stop command ({hex(race_header.id)}). Maybe something went wrong?"
                )
            else:
                if race_header.id in RaceId:
                    logging.debug(f"Received {RaceId(race_header.id)._name_} command")
                else:
                    logging.error(
                        f"Received unknown RACE command with ID: {hex(race_header.id)}"
                    )

    async def prepare_fota(self, reflash: bool):
        # Send partition query to identify the start address of where to write FOTA update
        await self.send_sync(FotaPartitionInfoQuery())
        if not self.fota_partition_addr:
            logging.error("Didn't get FOTA partition info, abort.")
            return False

        await self.send_sync(FotaStart())
        if not self.fota_start:
            logging.error("FOTA start failed!")
            return False

        await self.send_sync(FotaStartTransaction())

        # Not entirely sure what these do.
        await self.send_sync(FotaWriteState(b"\x01\x02"))
        await self.send_sync(FotaWriteState(b"\x10\x02"))

        # Only erase the partition if we're reflashing the partition during this update.
        if reflash:
            logging.info("Erasing FOTA partition.")
            await self.send_sync(
                ErasePartition(self.fota_partition_addr, self.fota_partition_length)
            )
            if not self.fota_partition_erased:
                logging.error("Error erasing FOTA partition.")
                return False

        return True

    async def _fota_flash(self, update_file: str):
        logging.info("FOTA Flashing starts now! This will take some time.")

        fsize = os.path.getsize(update_file)
        total_chunks = math.ceil(fsize / FOTAUpdater.CHUNK_SIZE)
        current_addr = self.fota_partition_addr
        retry_counter = 0
        retry = False
        with tqdm(
            total=total_chunks, desc="Writing FOTA Partition", unit="chunk"
        ) as pbar:
            with open(update_file, "rb") as f:
                while True:
                    if retry and retry_counter > 3:
                        break
                    # On retry, we don't want to read the next chunk
                    if not retry:
                        chunk = f.read(FOTAUpdater.CHUNK_SIZE * self.chunks_per_write)
                        if not chunk:
                            break

                    # fill chunk with FF if not big enough
                    if len(chunk) < 0x100 * self.chunks_per_write:
                        chunk += b"\xff" * (self.chunks_per_write * 0x100 - len(chunk))

                    await self.send_sync(WriteFlashPage(current_addr, chunk))

                    if self.fota_success:
                        current_addr += 0x300
                        pbar.update(self.chunks_per_write)
                        retry = False
                        retry_counter = 0
                    else:
                        retry_counter += 1
                        retry = True
                        logging.error(
                            f"There was an error at address {hex(current_addr)}. Retry ({retry_counter}/3)"
                        )

    async def update(self, update_file: str, reflash: bool):
        # set up reception handler
        await self.r.setup(self.recv)

        if not await self.prepare_fota(reflash):
            logging.error("Error in FOTA preparation. Try again")
            return

        if reflash:
            await self._fota_flash(update_file)

        # This will make the device check the signature or hash of the written update.
        await self.send_sync(FotaIntegrityCheck())
        if not self.fota_integrity_check:
            logging.error(
                "FOTA integrity check failed."
                + "\n\t- Perhaps there were errors during flashing. Try again with --dont-reflash."
                + "\n\t- If that doesn't work, try flashing again."
                + "\n\t- Make sure the image is properly signed or the hash is correct.",
                "red",
            )
            return

        # Not sure what this does.
        await self.send_sync(FotaWriteState(b"\x11\x02"))

        logging.info(
            color(
                "FOTA update flashing done. Sending FOTA commit. The device will now do some processing and then reboot, give it a few seconds",
                "yellow",
            )
        )
        await self.send_sync(FotaCommit())
