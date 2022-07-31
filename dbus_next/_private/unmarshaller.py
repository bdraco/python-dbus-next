from typing import Any
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
CTYPE_LENGTH = {
    "h": 2,  # int16
    "H": 2,  # uint16
    "i": 4,  # int32
    "I": 4,  # uint32
    "q": 8,  # int64
    "Q": 8,  # uint64
    "d": 8,  # double
    "I": 4,  # uint32
}

UNPACK_TABLE = {
    endian: {ctype: Struct(f"{UNPACK_SYMBOL[endian]}{ctype}") for ctype in CTYPE_LENGTH}
    for endian in (BIG_ENDIAN, LITTLE_ENDIAN)
}

DBUS_TO_CTYPE = {
    "n": "h",  # int16
    "q": "H",  # uint16
    "i": "i",  # int32
    "u": "I",  # uint32
    "x": "q",  # int64
    "t": "Q",  # uint64
    "d": "d",  # double
    "h": "I",  # uint32
}


class MarshallerStreamEndError(Exception):
    pass


class Unmarshaller:
    def __init__(self, stream, sock=None):
        self.unix_fds = []
        self.buf = bytearray()
        self.offset = 0
        self.stream = stream
        self.sock = sock
        self.message = None
        self.unpack_table = None
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

    def read(self, n, prefetch=False):
        """
        Read from underlying socket into buffer and advance offset accordingly.

        :arg n:
            Number of bytes to read. If not enough bytes are available in the
            buffer, read more from it.
        :arg prefetch:
            Do not update current offset after reading.

        :returns:
            Previous offset (before reading). To get the actual read bytes,
            use the returned value and self.buf.
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
        if missing_bytes > 0:
            data = read_sock(missing_bytes)
            if data == b"":
                raise EOFError()
            elif data is None:
                raise MarshallerStreamEndError()
            self.buf.extend(data)
            if len(data) != missing_bytes:
                raise MarshallerStreamEndError()
        prev = self.offset
        if not prefetch:
            self.offset += n
        return prev

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

    def align(self, n):
        padding = self._padding(self.offset, n)
        if padding > 0:
            self.read(padding)

    def read_byte(self, _=None):
        return self.buf[self.read(1)]

    def read_boolean(self, _=None):
        return bool(self.read_ctype("I", 4))

    def read_ctype(self, fmt: str, size: int) -> Any:
        padding = self._padding(self.offset, size)
        o = self.read(size + padding)
        return (self.unpack_table[fmt].unpack_from(self.buf, o + padding))[0]

    def read_string(self, _=None):
        str_length = self.read_ctype("I", 4)  # uint32
        o = self.read(str_length + 1)  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        return (memoryview(self.buf)[o : o + str_length]).tobytes().decode()

    def read_signature(self, _=None):
        signature_len = self.buf[self.read(1)]  # byte
        o = self.read(signature_len + 1)  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        return (memoryview(self.buf)[o : o + signature_len]).tobytes().decode()

    def read_variant(self, _=None):
        signature_tree = SignatureTree._get(self.read_signature())
        return Variant(signature_tree, self.read_argument(signature_tree.types[0]))

    def read_struct(self, type_: SignatureType):
        self.align(8)
        return [self.read_argument(child_type) for child_type in type_.children]

    def read_dict_entry(self, type_: SignatureType):
        self.align(8)
        return self.read_argument(type_.children[0]), self.read_argument(
            type_.children[1]
        )

    def read_array(self, type_: SignatureType):
        self.align(4)
        array_length = self.read_ctype("I", 4)  # uint32

        child_type = type_.children[0]
        if child_type.token in "xtd{(":
            # the first alignment is not included in the array size
            self.align(8)

        if child_type.token == "y":
            o = self.read(array_length)
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
        # If its a simple ctype, try this first as
        # its faster to dispatch to read_ctype
        ctype = DBUS_TO_CTYPE.get(type_.token)
        if ctype:
            return self.read_ctype(ctype, CTYPE_LENGTH[ctype])

        # If we need a complex reader, try this next
        reader = self.readers.get(type_.token)
        if reader:
            return reader(type_)
        raise Exception(f'dont know how to read yet: "{type_.token}"')

    def _unmarshall(self):
        self.offset = 0
        self.read(16, prefetch=True)
        header_start = self.read(16)
        _endian, _message_type, _flags, protocol_version = UNPACK_HEADER.unpack(
            memoryview(self.buf)[header_start : header_start + 4]
        )
        if _endian != LITTLE_ENDIAN and _endian != BIG_ENDIAN:
            raise InvalidMessageError("Expecting endianness as the first byte")
        self.unpack_table = UNPACK_TABLE[_endian]
        message_type = MessageType(_message_type)
        flags = MessageFlag(_flags)

        if protocol_version != PROTOCOL_VERSION:
            raise InvalidMessageError(
                f"got unknown protocol version: {protocol_version}"
            )

        body_len, serial, header_len = UNPACK_LENGTHS[_endian].unpack(
            memoryview(self.buf)[header_start + 4 : header_start + 16]
        )

        msg_len = header_len + self._padding(header_len, 8) + body_len
        self.read(msg_len, prefetch=True)
        # backtrack offset since header array length needs to be read again
        self.offset -= 4

        header_fields = {}
        for field_struct in self.read_argument(SignatureTree._get("a(yv)").types[0]):
            field = HeaderField(field_struct[0])
            header_fields[field.name] = field_struct[1].value

        self.align(8)

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
            message_type=message_type,
            flags=flags,
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
