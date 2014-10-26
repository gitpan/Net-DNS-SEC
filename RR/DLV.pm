package Net::DNS::RR::DLV;

#
# $Id: DLV.pm 1179 2014-03-19 21:46:58Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1179 $)[1];


use strict;
use base qw(Net::DNS::RR::DS);

no warnings;

=head1 NAME

Net::DNS::RR::DLV - DNS DLV resource record

=cut


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name DLV keytag algorithm digtype digest');

=head1 DESCRIPTION

DNS DLV resource record

This is a clone of the DS record and inherits all properties of
the Net::DNS::RR::DS class.

Please see the L<Net::DNS::RR::DS> perldocumentation for details.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.



=head1 COPYRIGHT

Copyright (c)2005 Olaf Kolkman (NLnet Labs)

All rights reserved.

This program is free software; you may redistribute it and/or
modify it under the same terms as Perl itself.

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::RR::DS>, RFC4431

=cut
