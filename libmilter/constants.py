# Copyright 2011 Chris Siebenmann
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Constants for the milter protocol.

# fmt: off

MILTER_VERSION      = 2         # Milter version we claim to speak
MILTER_CHUNK_SIZE   = 65535     # How large a SMFIC_BODY body can be

# Commands
SMFIC_ABORT     = 'A'
SMFIC_BODY      = 'B'   # body chunk
SMFIC_CONNECT   = 'C'   # connection information
SMFIC_MACRO     = 'D'   # define macro
SMFIC_BODYEOB   = 'E'   # final body chunk
SMFIC_HELO      = 'H'   # HELO or EHLO
SMFIC_QUIT_NC   = 'K'   # QUIT but new connection follows
SMFIC_HEADER    = 'L'
SMFIC_MAIL      = 'M'   # MAIL FROM
SMFIC_EOH       = 'N'
SMFIC_OPTNEG    = 'O'   # option negotiation
SMFIC_QUIT      = 'Q'
SMFIC_RCPT      = 'R'   # RCPT TO
SMFIC_DATA      = 'T'

# What the filter might do
SMFIF_ADDHDRS       = 0x0001    # add headers
SMFIF_CHGBODY       = 0x0002    # replace body
SMFIF_ADDRCPT       = 0x0004    # add recipients
SMFIF_DELRCPT       = 0x0008    # delete recipientes
SMFIF_CHGHDRS       = 0x0010    # change and delete headers
SMFIF_QUARANTINE    = 0x0020
SMFIF_CHGFROM       = 0x0040    # change envelope sender
SMFIF_ADDRCPT_PAR   = 0x0080    # add recipients including arguments
SMFIF_SETSYMLIST    = 0x0100    # send set of symbols that it wants

# bitmask of actions supported in each protocol version
SMFI_V1_ACTS = 0x000f
SMFI_V2_ACTS = 0x003f
SMFI_V6_ACTS = 0x01ff

# protocol negotiation
SMFIP_NOCONNECT     = 0x00000001    # MTA should not send connection info
SMFIP_NOHELO        = 0x00000002    # MTA should not send hello
SMFIP_NOMAIL        = 0x00000004    # MTA should not send MAIL
SMFIP_NORCPT        = 0x00000008    # MTA should not send RCPT
SMFIP_NOBODY        = 0x00000010    # MTA should not send body
SMFIP_NOHDRS        = 0x00000020    # MTA should not send headers
SMFIP_NOEOH         = 0x00000040    # MTA should not send EOH
SMFIP_NR_HDR        = 0x00000080    # No reply for headers
SMFIP_NOUNKNOWN     = 0x00000100    # MTA should not send unknown commands
SMFIP_NODATA        = 0x00000200    # MTA should not send DATA
SMFIP_SKIP          = 0x00000400    # MTA understands SMFIS_SKIP
SMFIP_RCPT_REJ      = 0x00000800    # MTA should also send rejected RCPTs
SMFIP_NR_CONN       = 0x00001000    # No reply for connect
SMFIP_NR_HELO       = 0x00002000    # No reply for HELO
SMFIP_NR_MAIL       = 0x00004000    # No reply for MAIL
SMFIP_NR_RCPT       = 0x00008000    # No reply for RCPT
SMFIP_NR_DATA       = 0x00010000    # No reply for DATA
SMFIP_NR_UNKN       = 0x00020000    # No reply for UNKN
SMFIP_NR_EOH        = 0x00040000    # No reply for eoh
SMFIP_NR_BODY       = 0x00080000    # No reply for body chunk
SMFIP_HDR_LEADSPC   = 0x00100000    # header value leading space
SMFIP_MDS_256K      = 0x10000000    # MILTER_MAX_DATA_SIZE=256K
SMFIP_MDS_1M        = 0x20000000    # MILTER_MAX_DATA_SIZE=1M

# bitmask of protocol steps supported in each version
SMFI_V1_PROT = 0x00003f
SMFI_V2_PROT = 0x00007f
SMFI_V6_PROT = 0x1fffff

# Acceptable response commands/codes to return to sendmail (with accompanying
# command data).  From sendmail's include/libmilter/mfdef.h
SMFIR_ADDRCPT       = '+'   # Add recipient
SMFIR_DELRCPT       = '-'   # Delete recipient
SMFIR_ADDRCPT_PAR   = '2'   # Add recipient (including ESMTP args)
SMFIR_SHUTDOWN      = '4'   # 421: shutdown (internal to MTA)
SMFIR_ACCEPT        = 'a'   # Accept
SMFIR_REPLBODY      = 'b'   # Replace body (chunk)
SMFIR_CONTINUE      = 'c'   # Continue
SMFIR_DISCARD       = 'd'   # Discard
SMFIR_CHGFROM       = 'e'   # Change envelope sender (from)
SMFIR_CONN_FAIL     = 'f'   # Cause a connection failure
SMFIR_ADDHEADER     = 'h'   # Add header
SMFIR_INSHEADER     = 'i'   # Insert header
SMFIR_SETSYMLIST    = 'l'   # Set list of symbols (macros)
SMFIR_CHGHEADER     = 'm'   # Change header
SMFIR_PROGRESS      = 'p'   # Progress
SMFIR_QUARANTINE    = 'q'   # Quarantine
SMFIR_REJECT        = 'r'   # Reject
SMFIR_SKIP          = 's'   # Skip
SMFIR_TEMPFAIL      = 't'   # Tempfail
SMFIR_REPLYCODE     = 'y'   # Reply code
