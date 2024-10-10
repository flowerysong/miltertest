# Copyright 2011 Chris Siebenmann
# Copyright 2024 Paul Arthur MacIain
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Support for having a milter protocol conversation over a network
# socket (or at least something that supports .recv).
# Much of this support is only useful for something doing the MTA side
# of the milter conversation.

from . import codec
from . import constants

__all__ = [
    'MilterConnection',
    'MilterError',
    'DISPOSITION_REPLIES',
    'EOM_REPLIES',
]


class MilterError(Exception):
    """Conversation sequence error"""


# Specific command sets:
DISPOSITION_REPLIES = frozenset(
    [
        constants.SMFIR_ACCEPT,
        constants.SMFIR_CONTINUE,
        constants.SMFIR_REJECT,
        constants.SMFIR_TEMPFAIL,
        constants.SMFIR_REPLYCODE,
        constants.SMFIR_DISCARD,
        constants.SMFIR_QUARANTINE,
    ]
)

EOM_REPLIES = frozenset(
    [
        *DISPOSITION_REPLIES,
        constants.SMFIR_ADDRCPT,
        constants.SMFIR_DELRCPT,
        constants.SMFIR_ADDRCPT_PAR,
        constants.SMFIR_REPLBODY,
        constants.SMFIR_CHGFROM,
        constants.SMFIR_ADDHEADER,
        constants.SMFIR_INSHEADER,
        constants.SMFIR_CHGHEADER,
    ]
)


class MilterConnection:
    """Maintain a buffered socket connection with another end that
    is speaking the milter protocol. This class supplies various
    convenience methods for handling aspects of the milter
    conversation."""

    def __init__(self, sock, blksize=16 * 1024):
        self.sock = sock
        self.buf = b''
        self.blksize = blksize
        self.action_flags = None
        self.protocol_flags = None

    def _recv(self, eof_ok=False):
        """Retrieve the next message from the connection message.
        Returns the decoded message as a tuple of (cmd, paramdict).
        Raises MilterDecodeError if we see EOF with an incomplete
        packet.

        If we see a clean EOF, we normally raise MilterError.
        If eof_ok is True, we instead return None."""
        while True:
            try:
                # .decode_msg will fail with an incomplete
                # error if self.buf is empty, so we don't
                # have to check for that ourselves.
                (rcmd, rdict, data) = codec.decode_msg(self.buf)
                self.buf = data
                return (rcmd, rdict)
            except codec.MilterIncomplete:
                # Fall through to read more data
                pass

            data = self.sock.recv(self.blksize)
            # Check for EOF on the recv.
            # If we have data left in self.buf, it axiomatically
            # failed to decode above and so it must be an
            # incomplete packet.
            if not data:
                if self.buf:
                    raise codec.MilterDecodeError('packet truncated by EOF')
                if not eof_ok:
                    raise MilterError('unexpected EOF')
                return None
            self.buf += data
            del data

    def recv(self, eof_ok=False):
        """Read the next real message, one that is not a SMFIR_PROGRESS
        notification. The arguments are for get_msg."""
        while True:
            r = self._recv(eof_ok)
            if not r or r[0] != constants.SMFIR_PROGRESS:
                return r

    def _send(self, cmd, **args):
        """Send an encoded milter message. The arguments are the
        same arguments that codec.encode_msg() takes."""
        self.sock.sendall(codec.encode_msg(cmd, **args))

    def send_macro(self, cmdcode, **args):
        """Send a SMFIC_MACRO message for the specific macro.
        The name and values are taken from the keyword arguments."""
        namevals = [x for items in args.items() for x in items]
        self._send(constants.SMFIC_MACRO, cmdcode=cmdcode, nameval=namevals)

    # The following methods are only useful if you are handling
    # the MTA side of the milter conversation.
    def send_get(self, cmd, **args):
        """Send a message (as with ._send()) and then wait for
        a real reply message."""
        self._send(cmd, **args)
        return self.recv()

    def send_get_specific(self, reply_cmds, cmd, **args):
        """Send a message and then wait for a real reply
        message. Raises MilterError if the reply has a
        command code not in reply_cmds."""
        r = self.send_get(cmd, **args)
        if r[0] not in reply_cmds:
            raise MilterError('unexpected response: ' + r[0])
        return r

    def send(self, cmd, **kwargs):
        """Send a message and wait for SMFIR_CONTINUE. If any other response
        is received, that's an error."""
        self.send_get_specific(constants.SMFIR_CONTINUE, cmd, **kwargs)

    def send_ar(self, cmd, **args):
        """Send a message and then wait for a real reply message
        that is from the accept/reject set."""
        return self.send_get_specific(DISPOSITION_REPLIES, cmd, **args)

    def send_body(self, body):
        """Send the body of a message, properly chunked and
        handling progress. Returns a progress response. If it
        is anything except SMFIR_CONTINUE, processing cannot
        continue because the body may not have been fully
        transmitted."""
        for cstart in range(0, len(body), constants.MILTER_CHUNK_SIZE):
            cend = cstart + constants.MILTER_CHUNK_SIZE
            blob = body[cstart:cend]
            r = self.send_ar(constants.SMFIC_BODY, buf=blob)
            if r[0] != constants.SMFIR_CONTINUE:
                raise MilterError(f'Unexpected reply to {constants.SMFIC_BODY}: {r}')
        return r

    def send_headers(self, headertuples):
        """Send message headers, handling progress; returns a
        progress response, normally SMFIR_CONTINUE. headertuples
        is a sequence of (header-name, header-value) tuples.

        If the response is anything but SMFIR_CONTINUE,
        processing cannot continue because the headers may not
        have been completely transmitted."""
        for hname, hval in headertuples:
            r = self.send_ar(constants.SMFIC_HEADER, name=hname, value=hval)
            if r[0] != constants.SMFIR_CONTINUE:
                raise MilterError(f'Unexpected reply to {constants.SMFIC_HEADER}: {r}')
        return r

    def send_eom(self):
        """Send EOM and collect any EOM actions"""
        res = []
        self._send(constants.SMFIC_BODYEOB)
        while True:
            msg = self.recv()
            res.append(msg)
            if msg[0] in DISPOSITION_REPLIES:
                return res

    # Option negotiation from the MTA and milter view.
    def optneg_mta(self, actions=constants.SMFI_V6_ACTS, protocol=constants.SMFI_V6_PROT, strict=True):
        """Perform the initial option negotiation as an MTA. Returns
        a tuple of (actions, protocol) bitmasks for what we support.
        If strict is True (the default), raises MilterError if
        the milter returns an SMFIC_OPTNEG that asks for things we
        told it that we do not support.
        """
        actions, protocol = codec.optneg_mta_capable(actions, protocol)
        self.sock.sendall(codec.encode_optneg(actions, protocol))
        r = self._recv()
        if r[0] != constants.SMFIC_OPTNEG:
            raise MilterError(f'Bad reply to SMFIR_OPTNEG, {r[0]}/{r[1]}')
        ract = r[1]['actions']
        rprot = r[1]['protocol']
        if strict:
            # There should be no bits outside what we claim to
            # support.
            if (ract & actions) != ract or (rprot & protocol) != rprot:
                raise MilterError(f'SMFIR_OPTNEG reply with unsupported bits in actions or protocol: 0x{ract:x}/0x{rprot:x}')
        else:
            ract = ract & actions
            rprot = rprot & protocol
        self.action_flags = ract
        self.protocol_flags = rprot
        return ract, rprot

    def optneg_milter(self, actions=constants.SMFI_V6_ACTS, protocol=0):
        """Perform the initial option negotiation as a milter,
        reading the MTA's SMFIR_OPTNEG and replying with ours.
        Returns a tuple of (actions, protocol) bitmasks for what
        both we and the MTA will do."""
        r = self._recv()
        if r[0] != constants.SMFIC_OPTNEG:
            raise MilterError(f'Expected SMFIR_OPTNEG, received {r[0]}/{r[1]}')
        ract, rprot = codec.optneg_milter_capable(r[1]['actions'], r[1]['protocol'], actions, protocol)
        self.sock.sendall(codec.encode_optneg(ract, rprot, is_milter=True))
        self.action_flags = ract
        self.protocol_flags = rprot
        return (ract, rprot)
