from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from ..message import Message
from .constants import (
    HeaderField,
    LITTLE_ENDIAN,
    BIG_ENDIAN,
    PROTOCOL_VERSION,
    HEADER_NAME_MAP,
)
from ..constants import MessageType, MessageFlag
from ..signature import SignatureTree, SignatureType, Variant
from ..errors import InvalidMessageError

import array
import contextlib
import socket
import sys
from struct import Struct

MAX_UNIX_FDS = 16

UNPACK_HEADER = Struct("BBBB")
UNPACK_SYMBOL = {LITTLE_ENDIAN: "<", BIG_ENDIAN: ">"}
UNPACK_LENGTHS = {BIG_ENDIAN: Struct(">III"), LITTLE_ENDIAN: Struct("<III")}


DBUS_TO_CTYPE = {
    "y": ("B", 1),  # byte
    "n": ("h", 2),  # int16
    "q": ("H", 2),  # uint16
    "i": ("i", 4),  # int32
    "u": ("I", 4),  # uint32
    "x": ("q", 8),  # int64
    "t": ("Q", 8),  # uint64
    "d": ("d", 8),  # double
    "h": ("I", 4),  # uint32
}

UNPACK_TABLE = {
    endian: {
        dbus_type: Struct(f"{UNPACK_SYMBOL[endian]}{ctype_len[0]}")
        for dbus_type, ctype_len in DBUS_TO_CTYPE.items()
    }
    for endian in (BIG_ENDIAN, LITTLE_ENDIAN)
}
HEADER_SIZE = 16

UINT32_SIGNATURE = SignatureTree._get("u").types[0]

HEADER_DESTINATION = HeaderField.DESTINATION.name
HEADER_PATH = HeaderField.PATH.name
HEADER_INTERFACE = HeaderField.INTERFACE.name
HEADER_MEMBER = HeaderField.MEMBER.name
HEADER_ERROR_NAME = HeaderField.ERROR_NAME.name
HEADER_REPLY_SERIAL = HeaderField.REPLY_SERIAL.name
HEADER_SENDER = HeaderField.SENDER.name


class MarshallerStreamEndError(Exception):
    pass


#
# Alignment padding is handled with the following formula below
#
# For any align value, the correct padding formula is:
#
#    (align - (offset % align)) % align
#
# However, if align is a power of 2 (always the case here), the slow MOD
# operator can be replaced by a bitwise AND:
#
#    (align - (offset & (align - 1))) & (align - 1)
#
# Which can be simplified to:
#
#    (-offset) & (align - 1)
#
#
class Unmarshaller:

    buf: bytearray
    view: memoryview
    message: Message
    unpack: Dict[str, Struct]

    def __init__(self, stream, sock=None):
        self.unix_fds: List[int] = []
        self.can_cast = False
        self.buf = None  # Actual buffer
        self.view = None  # Memory view of the buffer
        self.offset = 0
        self.stream = stream
        self.sock = sock
        self.message = None
        self.unpack = None

    def read_sock(self, length: int) -> bytes:
        """reads from the socket, storing any fds sent and handling errors
        from the read itself"""
        unix_fd_list = array.array("i")

        try:
            msg, ancdata, *_ = self.sock.recvmsg(
                length, socket.CMSG_LEN(MAX_UNIX_FDS * unix_fd_list.itemsize)
            )
        except BlockingIOError:
            raise MarshallerStreamEndError()

        for level, type_, data in ancdata:
            if not (level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS):
                continue
            unix_fd_list.frombytes(
                data[: len(data) - (len(data) % unix_fd_list.itemsize)]
            )
            self.unix_fds.extend(list(unix_fd_list))

        return msg

    def fetch(self, missing_bytes: int) -> bytes:
        """
        Read from underlying socket into buffer and advance offset accordingly.

        :arg n:
            Number of bytes to read. If not enough bytes are available in the
            buffer, read more from it.

        :returns:
            None
        """
        if self.sock is None:
            data: Union[bytes, bytearray] = bytearray(missing_bytes)
            if self.stream.readinto(data) != missing_bytes:
                raise MarshallerStreamEndError()
            return data

        data = self.read_sock(missing_bytes)
        if data == b"":
            raise EOFError()
        if data is None:
            raise MarshallerStreamEndError()
        if len(data) != missing_bytes:
            raise MarshallerStreamEndError()
        return data

    def read_boolean(self, _=None):
        return bool(self.read_argument(UINT32_SIGNATURE))

    def read_string(self, _=None):
        str_length = self.read_argument(UINT32_SIGNATURE)
        str_start = self.offset
        # read terminating '\0' byte as well (str_length + 1)
        self.offset += str_length + 1
        # This used to use a memoryview, but since all the data
        # is small, the extra overhead of converting the memoryview
        # back to bytes and decoding it made the read slower than
        # just using a bytearray.
        return self.buf[str_start : str_start + str_length].decode()

    def read_signature(self, _=None):
        signature_len = self.view[self.offset]  # byte
        o = self.offset + 1
        # read terminating '\0' byte as well (str_length + 1)
        self.offset = o + signature_len + 1
        # This used to use a memoryview, but since all the data
        # is small, the extra overhead of converting the memoryview
        # back to bytes and decoding it made the read slower than
        # just using a bytearray.
        return self.buf[o : o + signature_len].decode()

    def read_variant(self, _=None):
        tree = SignatureTree._get(self.read_signature())
        # verify in Variant is only useful on construction since
        # data is already guaranteed to be in the expected format
        # by the unpack so we set verify to False here
        return Variant(tree, self.read_argument(tree.types[0]), verify=False)

    def read_struct(self, type_: SignatureType):
        self.offset += -self.offset & 7  # align 8
        return [self.read_argument(child_type) for child_type in type_.children]

    def read_dict_entry(self, type_: SignatureType):
        self.offset += -self.offset & 7  # align 8
        return self.read_argument(type_.children[0]), self.read_argument(
            type_.children[1]
        )

    def read_array(self, type_: SignatureType):
        self.offset += -self.offset & 3  # align 4 for the array
        array_length = self.read_argument(UINT32_SIGNATURE)

        child_type = type_.children[0]
        if child_type.token in "xtd{(":
            # the first alignment is not included in the array size
            self.offset += -self.offset & 7  # align 8

        if child_type.token == "y":
            self.offset += array_length
            return self.buf[self.offset - array_length : self.offset]

        beginning_offset = self.offset

        if child_type.token == "{":
            result_dict = {}
            while self.offset - beginning_offset < array_length:
                key, value = self.read_dict_entry(child_type)
                result_dict[key] = value
            return result_dict

        result_list = []
        while self.offset - beginning_offset < array_length:
            result_list.append(self.read_argument(child_type))
        return result_list

    def read_argument(self, type_: SignatureType) -> Any:
        """Dispatch to an argument reader."""
        token = type_.token
        reader_ctype_size = self.readers[token]
        if reader_ctype_size[0]:  # complex type
            return reader_ctype_size[0](self, type_)
        size = reader_ctype_size[2]
        self.offset += size + (-self.offset & (size - 1))  # type: ignore # align
        if self.can_cast:
            return self.view[self.offset - size : self.offset].cast(
                reader_ctype_size[1]  # type: ignore
            )[0]
        return (self.unpack[token].unpack_from(self.view, self.offset - size))[0]

    def header_fields(self, header_length):
        """Header fields are always a(yv)."""
        beginning_offset = self.offset
        headers = {}
        while self.offset - beginning_offset < header_length:
            # Now read the y (byte) of struct (yv)
            self.offset += (-self.offset & 7) + 1  # align 8 + 1 for 'y' byte
            field_0 = self.view[self.offset - 1]

            # Now read the v (varient) of struct (yv)
            signature_len = self.view[self.offset]  # byte
            o = self.offset + 1
            self.offset += signature_len + 2  # one for the byte, one for the '\0'
            tree = SignatureTree._get(self.buf[o : o + signature_len].decode())
            headers[HEADER_NAME_MAP[field_0]] = self.read_argument(tree.types[0])
        return headers

    def _unmarshall(self):
        header_data = self.fetch(HEADER_SIZE)
        endian, message_type, flags, protocol_version = UNPACK_HEADER.unpack_from(
            header_data, 0
        )
        if endian != LITTLE_ENDIAN and endian != BIG_ENDIAN:
            raise InvalidMessageError("Expecting endianness as the first byte")

        if protocol_version != PROTOCOL_VERSION:
            raise InvalidMessageError(
                f"got unknown protocol version: {protocol_version}"
            )

        body_len, serial, header_len = UNPACK_LENGTHS[endian].unpack_from(
            header_data, 4
        )
        msg_len = header_len + (-header_len & 7) + body_len  # align 8
        if (sys.byteorder == "little" and endian == LITTLE_ENDIAN) or (
            sys.byteorder == "big" and endian == BIG_ENDIAN
        ):
            self.can_cast = True
        else:
            self.unpack = UNPACK_TABLE[endian]
        self.buf = self.fetch(msg_len)
        self.view = memoryview(self.buf)

        header_fields = self.header_fields(header_len)
        self.offset += -self.offset & 7  # align 8

        tree = SignatureTree._get(header_fields.get(HeaderField.SIGNATURE.name, ""))

        if body_len:
            body = [self.read_argument(type_) for type_ in tree.types]
        else:
            body = []

        self.message = Message(
            destination=header_fields.get(HEADER_DESTINATION),
            path=header_fields.get(HEADER_PATH),
            interface=header_fields.get(HEADER_INTERFACE),
            member=header_fields.get(HEADER_MEMBER),
            message_type=MessageType(message_type),
            flags=MessageFlag(flags),
            error_name=header_fields.get(HEADER_ERROR_NAME),
            reply_serial=header_fields.get(HEADER_REPLY_SERIAL),
            sender=header_fields.get(HEADER_SENDER),
            unix_fds=self.unix_fds,
            signature=tree,
            body=body,
            serial=serial,
        )

    def unmarshall(self):
        with contextlib.suppress(MarshallerStreamEndError):
            self._unmarshall()
            return self.message
        return None

    _complex_readers: Dict[
        str,
        Tuple[Callable[["Unmarshaller", SignatureType], Any], None, None],
    ] = {
        "b": (read_boolean, None, None),
        "o": (read_string, None, None),
        "s": (read_string, None, None),
        "g": (read_signature, None, None),
        "a": (read_array, None, None),
        "(": (read_struct, None, None),
        "{": (read_dict_entry, None, None),
        "v": (read_variant, None, None),
    }

    _ctype_readers: Dict[str, Tuple[None, str, int],] = {
        dbus_type: (None, *ctype_size)
        for dbus_type, ctype_size in DBUS_TO_CTYPE.items()
    }

    readers: Dict[
        str,
        Tuple[
            Optional[Callable[["Unmarshaller", SignatureType], Any]],
            Optional[str],
            Optional[int],
        ],
    ] = {
        **_complex_readers,
        **_ctype_readers,
    }
