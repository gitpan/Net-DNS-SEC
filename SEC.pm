
#
# $Id: SEC.pm,v 1.1 2002/06/04 12:34:51 olaf Exp $
#

package Net::DNS::SEC;
use Net::DNS;

use strict;
use vars qw($VERSION);
$VERSION = '0.02';


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DS

=head1 SYNOPSIS

C<use Net::DNS::SEC>;

With Net::DNS 0.21 and higher it is sufficient to 'use Net::DNS' to
have access to the secured RRs. If you depend on DNS security it is
probably better to 'use Net::DNS::SEC'.

=head1 DESCRIPTION

Pseudo package. 

See Net::DNS for usage.


=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::KEY>, L<Net::DNS::RR::SIG>,
L<Net::DNS::RR::NXT>, L<Net::DNS::RR::DS>.

=cut


=cut


