package Net::DNS::RR::NSEC;

#
# $Id: NSEC.pm 1276 2014-10-19 06:02:40Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1276 $)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::NSEC - DNS NSEC resource record

=cut


use integer;

use warnings;
use Net::DNS::DomainName;
use Net::DNS::Parameters;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	( $self->{nxtdname}, $offset ) = decode Net::DNS::DomainName(@_);
	$self->{typebm} = substr $$data, $offset, $limit - $offset;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{typebm};
	join '', $self->{nxtdname}->encode(), $self->{typebm};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{typebm};
	join ' ', $self->{nxtdname}->string(), $self->typelist;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->nxtdname(shift);
	$self->typelist(@_);
}


sub nxtdname {
	my $self = shift;

	$self->{nxtdname} = new Net::DNS::DomainName(shift) if scalar @_;
	$self->{nxtdname}->name if defined wantarray;
}


sub typelist {
	my $self = shift;

	$self->{typebm} = &_type2bm if scalar @_;

	my @type = defined wantarray ? &_bm2type( $self->{typebm} ) : ();
	return "@type" unless wantarray;
	return @type;
}


########################################


sub _type2bm {
	my @typearray;
	foreach my $typename ( map split( /\s+/, $_ ), @_ ) {
		next unless $typename;
		my $typenum = typebyname( uc $typename );
		my $window  = $typenum >> 8;
		next unless $window or $typenum < 128;		# skip meta type
		next if $typenum == 41;				# skip meta type
		my $bitnum = $typenum & 255;
		my $octet  = $bitnum >> 3;
		my $bit	   = $bitnum & 7;
		$typearray[$window][$octet] |= 0x80 >> $bit;
	}

	my $bitmap;
	my $window = 0;
	foreach (@typearray) {
		if ( my $pane = $typearray[$window] ) {
			my @content = map $_ || 0, @$pane;
			$bitmap .= pack 'CC C*', $window, scalar(@content), @content;
		}
		$window++;
	}

	return $bitmap || '';
}


sub _bm2type {
	my $bitmap = shift || '';
	my $index  = 0;
	my $limit  = length $bitmap;
	my @typelist;

	while ( $index < $limit ) {
		my ( $block, $size ) = unpack "\@$index C2", $bitmap;
		my @octet = unpack "\@$index xxC$size", $bitmap;
		$index += $size + 2;
		my $typenum = $block << 8;
		foreach my $octet (@octet) {
			$typenum += 8;
			my $i = $typenum;
			while ($octet) {
				--$i;
				push @typelist, typebyval($i) if $octet & 1;
				$octet = $octet >> 1;
			}
		}
	}

	return sort @typelist;
}


sub typebm {				## historical
	my $self = shift;
	return $self->{typebm} unless scalar @_;
	$self->{typebm} = shift;
}

sub _typearray2typebm {			## historical
	&_type2bm;
}

sub _typebm2typearray {			## historical
	&_bm2type;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name NSEC nxtdname typelist');

=head1 DESCRIPTION

Class for DNSSEC NSEC resource records.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 nxtdname

    $nxtdname = $rr->nxtdname;
    $rr->nxtdname( $nxtdname );

The Next Domain field contains the next owner name (in the
canonical ordering of the zone) that has authoritative data
or contains a delegation point NS RRset.

=head2 typelist

    @typelist = $rr->typelist;
    $typelist = $rr->typelist;

The Type List identifies the RRset types that exist at the NSEC RR
owner name.  When called in scalar context, the list is interpolated
into a string.


=head1 COPYRIGHT

Copyright (c)2001-2005 RIPE NCC.  Author Olaf M. Kolkman

All Rights Reserved

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

Package template (c)2009,2012 O.M.Kolkman and R.W.Franks.


=head1 SEE ALSO

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC4034, RFC3755

=cut
