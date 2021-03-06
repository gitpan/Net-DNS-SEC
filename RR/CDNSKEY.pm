package Net::DNS::RR::CDNSKEY;

#
# $Id: CDNSKEY.pm 1261 2014-09-11 10:14:45Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1261 $)[1];


use warnings;
use strict;
use base qw(Net::DNS::RR::DNSKEY);

=head1 NAME

Net::DNS::RR::CDNSKEY - DNS CDNSKEY resource record

=cut


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name CDNSKEY flags protocol algorithm publickey');

=head1 DESCRIPTION

DNS Child DNSKEY resource record

This is a clone of the DNSKEY record and inherits all properties of
the Net::DNS::RR::DNSKEY class.

Please see the L<Net::DNS::RR::DNSKEY> perl documentation for details.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.



=head1 COPYRIGHT

Copyright (c)2014 Dick Franks

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::RR::DNSKEY>, RFC7344

=cut
