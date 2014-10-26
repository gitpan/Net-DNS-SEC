
#
# $Id: SEC.pm,v 1.7 2003/01/08 08:13:09 olaf Exp $
#

package Net::DNS::SEC;
use Net::DNS;

use strict;
use vars qw($VERSION);
$VERSION = '0.10';


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DNS

=head1 SYNOPSIS

C<use Net::DNS>;

Net::DNS::SEC does not contain any code.

=head1 DESCRIPTION

The Net::DSN::SEC package provides the resource records that are
needed for Secure DNS (RFC2535). DNSSEC is a protocol that is still
under development.

We have currently implemented the RFC2535 specifications with addition 
of the 'delegation-signer' draft and SIG0 support. That later is useful for
dynamic updates with public keys.

RSA and DSA crypto routines are supported.

For details see Net::DNS::RR::SIG, Net::DNS::RR:KEY, Net::DNS::RR::NXT
and Net::DNS::RR:DS.

Net::DNS will load the modules for the secure RRs when they are
available through the Net::DNS::SEC package.

See Net::DNS for general help.


=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::KEY>, L<Net::DNS::RR::SIG>,
L<Net::DNS::RR::NXT>, L<Net::DNS::RR::DS>.

=cut


=cut


