"""SolarEdge input data and file management."""

import logging
import sys
from pathlib import Path

import serial

logger = logging.getLogger(__name__)


def openSerial(inFileName, baudRate):
    """
    Open the serial device in_file_name at baud_rate.

    Args:
        in_file_name: The name of the serial device.
        baud_rate: The baud rate to open it at.

    Returns:
        The open serial port.
    """
    return serial.Serial(inFileName, baudrate=baudRate)


def openInFile(inFileName):
    """
    Open the data source for reading in binary mode.

    The name "stdin" gives the binary buffer of standard input instead.

    Args:
        in_file_name: The name of the file to open, or "stdin".

    Returns:
        The binary file object to read the data from.
    """
    if inFileName == "stdin":
        return sys.stdin.buffer
    # Explicitly specify mode rb to keep Windows happy!
    return Path(inFileName).open("rb")


def closeData(dataFile):
    """Close the data source, and log its name."""
    logger.info("closing %s", dataFile.name)
    dataFile.close()


def openOutFile(fileName, writeMode="wb"):
    """
    Open the output file in write_mode, or return None if no name is given.

    The tokens __date__ and __datetime__ in the name are replaced by the
    current date, and the current date and time. The parent directories of
    the file are created when they are missing. An existing file is never
    overwritten in write mode, the next free name from next_free_file_name()
    is used instead.

    Args:
        file_name: The name of the file, which may be empty or None.
        write_mode: The mode to open the file in.

    Returns:
        The open file, or None if no name is given.
    """
    if fileName:
        return Path(fileName).open(writeMode)
    return None


def closeOutFiles(recFile, outFile):
    """Close the record and output files, logging the name of each closed."""
    if recFile:
        logger.info("closing %s", recFile.name)
        recFile.close()
    if outFile:
        logger.info("closing %s", outFile.name)
        outFile.close()
