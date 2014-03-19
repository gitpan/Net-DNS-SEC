package Net::DNS::SEC;

#
# $Id: SEC.pm 1179 2014-03-19 21:46:58Z willem $
#
use vars qw($VERSION $SVNVERSION);
$VERSION    = '0.17_4';
$SVNVERSION = (qw$LastChangedRevision: 1179 $)[1];


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DNS

=head1 SYNOPSIS

    use Net::DNS::SEC;

=head1 DESCRIPTION

The Net::DNS::SEC suite provides the additional DNS resource records
required to support DNSSEC as described in RFC4033, 4034, 4035 and
subsequent related documents.

Net::DNS::SEC is installed as an extension to an existing Net::DNS
installation.

The extended package features are made visible by substituting
Net::DNS::SEC for Net::DNS in the use declaration.

=cut


use strict;
use base qw(Exporter);

use Net::DNS 0.69 qw(:DEFAULT);

use vars qw(@EXPORT);
@EXPORT = ( @Net::DNS::EXPORT, qw(algorithm digtype key_difference) );


use integer;
use warnings;
use Carp;

require Net::DNS::RR::DS;

new Net::DNS::RR( type => $_ ) for qw(SIG RRSIG DLV);		# pre-load RR with create() constructor


=head1 UTILITY FUNCTIONS

=head2 algorithm

    $mnemonic = algorithm( 5 );
    $numeric  = algorithm( 'RSA-SHA1' );
    print "algorithm mnemonic\t", $mnemonic, "\n";
    print "algorithm number:\t",  $numeric,  "\n";

algorithm() provides conversions between an algorithm code number and
the corresponding mnemonic.

=cut

sub algorithm { &Net::DNS::RR::DS::algorithm; }


=head2 digtype

    $mnemonic = digtype( 2 );
    $numeric  = digtype( 'SHA-256' );
    print "digest type mnemonic\t", $mnemonic, "\n";
    print "digest type number:\t",  $numeric,  "\n";

digtype() provides conversions between a digest type number and the
corresponding mnemonic.

=cut

sub digtype { &Net::DNS::RR::DS::digtype; }


=head2 key_difference

    @result = key_difference( \@a, \@b );

Fills @result with all keys in array @a that are not in array @b.

=cut

my $errmsg = 'array argument contains unexpected %s object';

sub key_difference {
	my $a = shift;
	my $b = shift;
	my $r = shift;			## 0.17 interface

	my ($x) = grep !$_->isa('Net::DNS::RR::DNSKEY'), @$a, @$b;

	if ($r) {			## 0.17 interface
		return sprintf $errmsg, ref($x) if $x;

		my %index = map { ( $_->privatekeyname, 1 ) } @$b;
		@$r = grep { !$index{$_->privatekeyname} } @$a;
		return (0);
	}

	croak sprintf $errmsg, ref($x) if $x;

	my %index = map { ( $_->privatekeyname, 1 ) } @$b;
	my @r = grep { !$index{$_->privatekeyname} } @$a;
	return @r;
}


1;
__END__


=head1 COPYRIGHT

Copyright (c)2001-2005 RIPE NCC.  Author Olaf M. Kolkman

All Rights Reserved


=head1 LICENSE

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be used
in advertising or publicity pertaining to distribution of the software
without specific prior written permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO
EVENT SHALL AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE.


=head1 SEE ALSO

L<perl>, L<Net::DNS>,
L<Net::DNS::RR::DLV>, L<Net::DNS::RR::DNSKEY>, L<Net::DNS::RR::DS>,
L<Net::DNS::RR::NSEC>, L<Net::DNS::RR::NSEC3>, L<Net::DNS::RR::NSEC3PARAM>,
L<Net::DNS::RR::RRSIG>,
L<Net::DNS::RR::KEY>, L<Net::DNS::RR::SIG>,
RFC4033, RFC4034, RFC4035

=cut

