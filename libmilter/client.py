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
    'MilterError',
    'Milter',
    'accept_reject_replies',
    'bodyeob_replies',
]


class MilterError(Exception):
    """Conversation sequence error"""


# Specific command sets:
# accept/reject actions
accept_reject_replies = frozenset(
    [
        constants.SMFIR_ACCEPT,
        constants.SMFIR_CONTINUE,
        constants.SMFIR_REJECT,
        constants.SMFIR_TEMPFAIL,
        constants.SMFIR_REPLYCODE,
        constants.SMFIR_DISCARD,
    ]
)

# actions valid after BODYEOB
bodyeob_replies = frozenset(
    [
        *accept_reject_replies,
        constants.SMFIR_ADDHEADER,
        constants.SMFIR_CHGHEADER,
        constants.SMFIR_REPLBODY,
        constants.SMFIR_ADDRCPT,
        constants.SMFIR_DELRCPT,
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

    def get_msg(self, eof_ok=False):
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
                # This falls through to cause us to read
                # stuff.
                pass

            data = self.sock.recv(self.blksize)
            # Check for EOF on the read.
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

    def get_real_msg(self, eof_ok=False):
        """Read the next real message, one that is not a SMFIR_PROGRESS
        notification. The arguments are for get_msg."""
        while True:
            r = self.get_msg(eof_ok)
            if not r or r[0] != constants.SMFIR_PROGRESS:
                return r

    def send(self, cmd, **args):
        """Send an encoded milter message. The arguments are the
        same arguments that codec.encode_msg() takes."""
        self.sock.sendall(codec.encode_msg(cmd, **args))

    def send_macro(self, cmdcode, **args):
        """Send a SMFIC_MACRO message for the specific macro.
        The name and values are taken from the keyword arguments."""
        namevals = [x for items in args.items() for x in items]
        self.send(constants.SMFIC_MACRO, cmdcode=cmdcode, nameval=namevals)

    # The following methods are only useful if you are handling
    # the MTA side of the milter conversation.
    def send_get(self, cmd, **args):
        """Send a message (as with .send()) and then wait for
        a real reply message."""
        self.send(cmd, **args)
        return self.get_real_msg()

    def send_get_specific(self, reply_cmds, cmd, **args):
        """Send a message and then wait for a real reply
        message. Raises MilterError if the reply has a
        command code not in reply_cmds."""
        r = self.send_get(cmd, **args)
        if r[0] not in reply_cmds:
            raise MilterError('unexpected response: ' + r[0])
        return r

    def send_ar(self, cmd, **args):
        """Send a message and then wait for a real reply message
        that is from the accept/reject set."""
        return self.send_get_specific(accept_reject_replies, cmd, **args)

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

    # Option negotiation from the MTA and milter view.
    def optneg_mta(self, actions=constants.SMFI_V2_ACTS, protocol=constants.SMFI_V2_PROT, strict=True):
        """Perform the initial option negocation as a MTA. Returns
        a tuple of (actions, protocol) bitmasks for what we support.
        If strict is True (the default), raises MilterError if
        the milter returns a SMFIR_OPTNEG that asks for things we
        told it that we do not support.

        Can optionally be passed more restrictive values for actions
        and protocol, but this is not recommended; milters may dislike
        it enough to disconnect abruptly on you."""
        actions, protocol = codec.optneg_mta_capable(actions, protocol)
        self.sock.sendall(codec.encode_optneg(actions, protocol))
        r = self.get_msg()
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
        return ract, rprot

    def optneg_milter(self, actions=constants.SMFI_V2_ACTS, protocol=0):
        """Perform the initial option negotiation as a milter,
        reading the MTA's SMFIR_OPTNEG and replying with ours.
        Returns a tuple of (actions, protocol) bitmasks for what
        both we and the MTA will do."""
        r = self.get_msg()
        if r[0] != constants.SMFIC_OPTNEG:
            raise MilterError(f'Expected SMFIR_OPTNEG, received {r[0]}/{r[1]}')
        ract, rprot = codec.optneg_milter_capable(r[1]['actions'], r[1]['protocol'], actions, protocol)
        self.sock.sendall(codec.encode_optneg(ract, rprot, is_milter=True))
        return (ract, rprot)
