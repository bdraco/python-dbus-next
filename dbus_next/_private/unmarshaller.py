from typing import Any, Dict, Optional
from ..message import Message
from .constants import HeaderField, LITTLE_ENDIAN, BIG_ENDIAN, PROTOCOL_VERSION
from ..constants import MessageType, MessageFlag
from ..signature import SignatureTree, SignatureType, Variant
from ..errors import InvalidMessageError

import array
import socket
from struct import Struct

MAX_UNIX_FDS = 16

UNPACK_HEADER = Struct("BBBB")
UNPACK_SYMBOL = {LITTLE_ENDIAN: "<", BIG_ENDIAN: ">"}
UNPACK_LENGTHS = {BIG_ENDIAN: Struct(">III"), LITTLE_ENDIAN: Struct("<III")}
_CTYPE_LENGTH = {
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


class MarshallerStreamEndError(Exception):
    pass


#
# Padding is handled with the following formula below
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
        self.unix_fds = []
        self.buf = bytearray()
        self.offset = 0
        self.stream = stream
        self.sock = sock
        self.message: Optional[Message] = None
        self.unpack: Optional[Dict[str, Struct]] = None
        self.readers = {
            "y": self.read_byte,
            "b": self.read_boolean,
            "o": self.read_string,
            "s": self.read_string,
            "g": self.read_signature,
            "a": self.read_array,
            "(": self.read_struct,
            "{": self.read_dict_entry,
            "v": self.read_variant,
        }

    def fetch(self, n: int) -> None:
        """
        Read from underlying socket into buffer and advance offset accordingly.

        :arg n:
            Number of bytes to read. If not enough bytes are available in the
            buffer, read more from it.

        :returns:
            None
        """

        def read_sock(length):
            """reads from the socket, storing any fds sent and handling errors
            from the read itself"""
            if self.sock is not None:
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
            else:
                return self.stream.read(length)

        # store previously read data in a buffer so we can resume on socket
        # interruptions
        missing_bytes = n - (len(self.buf) - self.offset)
        if missing_bytes <= 0:
            return
        data = read_sock(missing_bytes)
        if data == b"":
            raise EOFError()
        elif data is None:
            raise MarshallerStreamEndError()
        elif len(data) != missing_bytes:
            raise MarshallerStreamEndError()
        self.buf.extend(data)

    @staticmethod
    def _padding(offset, align):
        """
        Get padding bytes to get to the next align bytes mark.

        For any align value, the correct padding formula is:

            (align - (offset % align)) % align

        However, if align is a power of 2 (always the case here), the slow MOD
        operator can be replaced by a bitwise AND:

            (align - (offset & (align - 1))) & (align - 1)

        Which can be simplified to:

            (-offset) & (align - 1)
        """
        return (-offset) & (align - 1)

    def read_byte(self, _=None):
        self.offset += 1
        return self.buf[self.offset - 1]

    def read_boolean(self, _=None):
        return bool(self.read_simple_token("u"))  # uint32

    def read_simple_token(self, dbus_type: str) -> Any:
        # The offset is the size plus the padding
        size = DBUS_TYPE_LENGTH[dbus_type]
        self.offset += size + (-self.offset & (size - 1))
        return (self.unpack[dbus_type].unpack_from(self.buf, self.offset - size))[0]

    def read_string(self, _=None):
        str_length = self.read_simple_token("u")  # uint32
        o = self.offset
        self.offset += str_length + 1  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        return (memoryview(self.buf)[o : o + str_length]).tobytes().decode()

    def read_signature(self, _=None):
        signature_len = self.buf[self.offset]  # byte
        o = self.offset + 1
        self.offset += 1 + signature_len + 1  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        return (memoryview(self.buf)[o : o + signature_len]).tobytes().decode()

    def read_variant(self, _=None):
        signature_tree = SignatureTree._get(self.read_signature())
        return Variant(signature_tree, self.read_argument(signature_tree.types[0]))

    def read_struct(self, type_: SignatureType):
        self.offset += -self.offset & 7  # align 8
        return [self.read_argument(child_type) for child_type in type_.children]

    def read_dict_entry(self, type_: SignatureType):
        self.offset += -self.offset & 7  # align 8
        return self.read_argument(type_.children[0]), self.read_argument(
            type_.children[1]
        )

    def read_array(self, type_: SignatureType):
        self.offset += -self.offset & 3  # align 4
        array_length = self.read_simple_token("u")  # uint32

        child_type = type_.children[0]
        if child_type.token in "xtd{(":
            # the first alignment is not included in the array size
            self.offset += -self.offset & 7  # align 8

        if child_type.token == "y":
            o = self.offset
            self.offset += array_length
            # avoid buffer copies when slicing
            return (memoryview(self.buf)[o : o + array_length]).tobytes()

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
        # If its a simple type, try this first
        if type_.token in self.unpack:
            return self.read_simple_token(type_.token)

        # If we need a complex reader, try this next
        reader = self.readers.get(type_.token)
        if reader:
            return reader(type_)
        raise Exception(f'dont know how to read yet: "{type_.token}"')

    def _unmarshall(self):
        self.fetch(16)
        header_start = self.offset
        self.offset += 16
        endian, message_type, flags, protocol_version = UNPACK_HEADER.unpack_from(
            self.buf, header_start
        )
        if endian != LITTLE_ENDIAN and endian != BIG_ENDIAN:
            raise InvalidMessageError("Expecting endianness as the first byte")
        self.unpack = UNPACK_TABLE[endian]

        if protocol_version != PROTOCOL_VERSION:
            raise InvalidMessageError(
                f"got unknown protocol version: {protocol_version}"
            )

        body_len, serial, header_len = UNPACK_LENGTHS[endian].unpack_from(
            self.buf, header_start + 4
        )

        msg_len = header_len + (-header_len & 7) + body_len  # padding 8
        self.fetch(msg_len)
        # backtrack offset since header array length needs to be read again
        self.offset -= 4

        header_fields = {
            HeaderField(field_struct[0]).name: field_struct[1].value
            for field_struct in self.read_argument(SignatureTree._get("a(yv)").types[0])
        }
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
        try:
            self._unmarshall()
            return self.message
        except MarshallerStreamEndError:
            return None
