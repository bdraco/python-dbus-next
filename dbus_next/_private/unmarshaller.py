from typing import Any, Dict, List, Optional
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
from struct import Struct

MAX_UNIX_FDS = 16

UNPACK_HEADER = Struct("BBBB")
UNPACK_SYMBOL = {LITTLE_ENDIAN: "<", BIG_ENDIAN: ">"}
UNPACK_LENGTHS = {BIG_ENDIAN: Struct(">III"), LITTLE_ENDIAN: Struct("<III")}
_CTYPE_LENGTH = {
    "B": 1,  # byte
    "h": 2,  # int16
    "H": 2,  # uint16
    "i": 4,  # int32
    "I": 4,  # uint32
    "q": 8,  # int64
    "Q": 8,  # uint64
    "d": 8,  # double
    "I": 4,  # uint32
}

_DBUS_TO_CTYPE = {
    "y": "B",  # byte
    "n": "h",  # int16
    "q": "H",  # uint16
    "i": "i",  # int32
    "u": "I",  # uint32
    "x": "q",  # int64
    "t": "Q",  # uint64
    "d": "d",  # double
    "h": "I",  # uint32
}

DBUS_TYPE_LENGTH = {
    dbus_type: _CTYPE_LENGTH[ctype] for dbus_type, ctype in _DBUS_TO_CTYPE.items()
}
UNPACK_TABLE = {
    endian: {
        dbus_type: Struct(f"{UNPACK_SYMBOL[endian]}{ctype}")
        for dbus_type, ctype in _DBUS_TO_CTYPE.items()
    }
    for endian in (BIG_ENDIAN, LITTLE_ENDIAN)
}
HEADER_SIZE = 16


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
    def __init__(self, stream, sock=None):
        self.unix_fds: List[int] = []
        self.buf: Optional[bytearray] = None  # Actual buffer
        self.view: Optional[memoryview] = None  # Memory view of the buffer
        self.offset = 0
        self.stream = stream
        self.sock = sock
        self.message: Optional[Message] = None
        self.unpack: Optional[Dict[str, Struct]] = None

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
        if self.sock is not None:
            data = self.read_sock(missing_bytes)
        else:
            data = self.stream.read(missing_bytes)
        if data == b"":
            raise EOFError()
        if data is None:
            raise MarshallerStreamEndError()
        if len(data) != missing_bytes:
            raise MarshallerStreamEndError()
        return data

    def read_boolean(self, _=None):
        self.offset += 4 + (-self.offset & 3)  # uint32 + align 4
        return bool(self.unpack["u"].unpack_from(self.view, self.offset - 4)[0])

    def read_string(self, _=None):
        uint_32_start = self.offset + (-self.offset & 3)  # align 4
        str_length = (self.unpack["u"].unpack_from(self.view, uint_32_start))[0]
        # read terminating '\0' byte as well (str_length + 1)
        self.offset = uint_32_start + 4 + str_length + 1
        return self.view[uint_32_start + 4 : self.offset - 1].tobytes().decode()

    def read_signature(self, _=None):
        signature_len = self.view[self.offset]  # byte
        o = self.offset + 1
        # read terminating '\0' byte as well (signature_len + 1)
        self.offset = o + signature_len + 1
        return self.buf[o : o + signature_len].decode()

    def read_variant(self, _=None):
        signature_tree = SignatureTree._get(self.read_signature())
        # verify in Variant is only useful on construction since
        # data is already guaranteed to be in the expected format
        # by the unpack so we set verify to False here
        return Variant(
            signature_tree, self.read_argument(signature_tree.types[0]), verify=False
        )

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
        self.offset += 4 + (-self.offset & 3)  # uint32 + align 4 for the uint32
        array_length = self.unpack["u"].unpack_from(self.view, self.offset - 4)[0]

        child_type = type_.children[0]
        if child_type.token in "xtd{(":
            # the first alignment is not included in the array size
            self.offset += -self.offset & 7  # align 8

        if child_type.token == "y":
            self.offset += array_length
            return self.view[self.offset - array_length : self.offset].tobytes()

        beginning_offset = self.offset

        if child_type.token == "{":
            result = {}
            while self.offset - beginning_offset < array_length:
                key, value = self.read_dict_entry(child_type)
                result[key] = value
            return result

        result = []
        while self.offset - beginning_offset < array_length:
            result.append(self.read_argument(child_type))
        return result

    def read_argument(self, type_: SignatureType) -> Any:
        """Dispatch to an argument reader."""
        token = type_.token
        if token in self.unpack:
            size = DBUS_TYPE_LENGTH[token]
            self.offset += size + (-self.offset & (size - 1))  # align
            return (self.unpack[token].unpack_from(self.view, self.offset - size))[0]

        # If we need a complex reader, try this next
        reader = self.readers.get(token)
        if reader:
            return reader(self, type_)
        raise Exception(f'dont know how to read yet: "{token}"')

    def header_fields(self, header_length):
        """Header fields are always a(yv)."""
        beginning_offset = self.offset
        headers = {}
        while self.offset - beginning_offset < header_length:
            # Now read the struct (yv)
            self.offset += (-self.offset & 7) + 1  # align 8 + 1 for 'y' byte
            field_0 = self.view[self.offset - 1]
            headers[HEADER_NAME_MAP[field_0]] = self.read_variant().value
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
        self.unpack = UNPACK_TABLE[endian]
        self.buf = self.fetch(msg_len)
        self.view = memoryview(self.buf)

        header_fields = self.header_fields(header_len)
        self.offset += -self.offset & 7  # align 8

        signature_tree = SignatureTree._get(
            header_fields.get(HeaderField.SIGNATURE.name, "")
        )
        # unix_fds = header_fields.get(HeaderField.UNIX_FDS.name, 0)

        if body_len:
            body = [self.read_argument(type_) for type_ in signature_tree.types]
        else:
            body = []

        self.message = Message(
            destination=header_fields.get(HeaderField.DESTINATION.name),
            path=header_fields.get(HeaderField.PATH.name),
            interface=header_fields.get(HeaderField.INTERFACE.name),
            member=header_fields.get(HeaderField.MEMBER.name),
            message_type=MessageType(message_type),
            flags=MessageFlag(flags),
            error_name=header_fields.get(HeaderField.ERROR_NAME.name),
            reply_serial=header_fields.get(HeaderField.REPLY_SERIAL.name),
            sender=header_fields.get(HeaderField.SENDER.name),
            unix_fds=self.unix_fds,
            signature=signature_tree,
            body=body,
            serial=serial,
        )

    def unmarshall(self):
        with contextlib.suppress(MarshallerStreamEndError):
            self._unmarshall()
            return self.message
        return None

    readers = {
        "b": read_boolean,
        "o": read_string,
        "s": read_string,
        "g": read_signature,
        "a": read_array,
        "(": read_struct,
        "{": read_dict_entry,
        "v": read_variant,
    }
