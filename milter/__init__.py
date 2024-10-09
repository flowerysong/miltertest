# Copyright 2011 Chris Siebenmann
# GNU General Public License v3.0 (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# I'm not sure what 'import milter' should do right now, but for now let's
# make it import everything useful.
__doc__ = """A collection of tools for dealing with the sendmail milter protocol.

Useful submodules are milter.codec and milter.convo. See their
documentation for details."""

from consts import *
import codec
import convo
