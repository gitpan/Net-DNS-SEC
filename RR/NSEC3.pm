package Net::DNS::RR::NSEC3;

#
# $Id: NSEC3.pm 1271 2014-10-10 21:55:38Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1271 $)[1];


use strict;
use base qw(Net::DNS::RR::NSEC);

=head1 NAME

Net::DNS::RR::NSEC3 - DNS NSEC3 resource record

=cut


use integer;

use warnings;
use Carp;
use MIME::Base32;

use base qw(Exporter);
use vars qw(@EXPORT_OK);
@EXPORT_OK = qw(name2hash);

require Net::DNS::DomainName;

eval { require Digest::SHA };		## optional for simple Net::DNS RR

my %digest = (
	'1' => ['Digest::SHA', 1],				# RFC3658
	);

{
	my @digestbyname = (
		'SHA-1' => 1,					# RFC3658
		);

	my @digestbyalias = ( 'SHA' => 1 );

	my %digestbyval = reverse @digestbyname;

	my @digestbynum = map { ( $_, 0 + $_ ) } keys %digestbyval;    # accept algorithm number

	my %digestbyname = map { s /[^A-Za-z0-9]//g; $_ } @digestbyalias, @digestbyname, @digestbynum;


	sub digestbyname {
		my $name = shift;
		my $key	 = uc $name;				# synthetic key
		$key =~ s /[^A-Z0-9]//g;			# strip non-alphanumerics
		return $digestbyname{$key} || croak "unknown digest type $name";
	}

	sub digestbyval {
		my $value = shift;
		return $digestbyval{$value} || $value;
	}
}


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	my $ssize = unpack "\@$offset x4 C", $$data;
	@{$self}{qw(algorithm flags iterations saltbin)} = unpack "\@$offset CCnx a$ssize", $$data;
	$offset += 5 + $ssize;
	my $hsize = unpack "\@$offset C",	  $$data;
	my $hname = unpack "\@$offset x a$hsize", $$data;
	$self->hnxtname( MIME::Base32::encode $hname, '' );
	$offset += 1 + $hsize;
	$self->{typebm} = substr $$data, $offset, ( $limit - $offset );
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	return '' unless $self->{typebm};
	my $salt = $self->saltbin;
	my $hash = MIME::Base32::decode uc( $self->hnxtname );
	pack 'CCn C a* C a* a*', $self->algorithm, $self->flags, $self->iterations,
			length($salt), $salt,
			length($hash), $hash,
			$self->{typebm};
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless $self->{typebm};
	join ' ', $self->algorithm, $self->flags, $self->iterations,
			$self->salt || '-',
			$self->hnxtname,
			$self->typelist;
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	$self->algorithm(shift);
	$self->flags(shift);
	$self->iterations(shift);
	my $salt = shift;
	$self->salt($salt) unless $salt eq '-';
	$self->hnxtname(shift);
	$self->typelist(@_);
}


sub defaults() {			## specify RR attribute default values
	my $self = shift;

	$self->parse_rdata( 1, 0, 0, '' );
}


sub algorithm {
	my ( $self, $arg ) = @_;

	unless ( ref($self) ) {		## class method or simple function
		my $argn = pop || croak 'undefined argument';
		return $argn =~ /[^0-9]/ ? digestbyname($argn) : digestbyval($argn);
	}

	return $self->{algorithm} unless defined $arg;
	return digestbyval( $self->{algorithm} ) if $arg =~ /MNEMONIC/i;
	return $self->{algorithm} = digestbyname($arg);
}


sub flags {
	my $self = shift;

	$self->{flags} = 0 + shift if scalar @_;
	return $self->{flags} || 0;
}


sub iterations {
	my $self = shift;

	$self->{iterations} = 0 + shift if scalar @_;
	return $self->{iterations} || 0;
}


sub salt {
	my $self = shift;

	$self->saltbin( pack "H*", map { die "!hex!" if m/[^0-9A-Fa-f]/; $_ } join "", @_ ) if scalar @_;
	unpack "H*", $self->saltbin() if defined wantarray;
}


sub saltbin {
	my $self = shift;

	$self->{saltbin} = shift if scalar @_;
	$self->{saltbin} || "";
}


sub hnxtname {
	my $self = shift;
	return $self->{hnxtname} unless scalar @_;
	$self->{hnxtname} = lc( shift || '' );
}


sub covered {
	my $self = shift;
	my $name = lc( shift || '' );

	# first test if the domain name is in the NSEC zone.
	my @domainlabels = new Net::DNS::DomainName($name)->_wire;
	my ( $ownlabel, @zonelabels ) = $self->{owner}->_wire;
	my $ownername = lc( $ownlabel || '' );

	foreach ( reverse @zonelabels ) {
		return 0 unless lc($_) eq ( pop(@domainlabels) || '' );
	}

	my $hnxtname = $self->hnxtname;

	my $hashedname = name2hash( $self->algorithm, $name, $self->iterations, $self->saltbin );

	my $hashorder = $ownername cmp $hnxtname;

	if ( $hashorder < 0 ) {
		return 0 unless ( $ownername cmp $hashedname ) < 0;
		return 1 if ( $hashedname cmp $hnxtname ) < 0;

	} elsif ($hashorder) {					# last name in zone
		return 1 if ( $hashedname cmp $hnxtname ) < 0;
		return 1 if ( $ownername cmp $hashedname ) < 0;

	} else {						# only name in zone
		return 1;
	}

	return 0;
}


sub match {
	my $self = shift;
	my $name = shift;

	my ($ownername) = $self->{owner}->_wire;
	my $hashedname = name2hash( $self->algorithm, $name, $self->iterations, $self->saltbin );

	return $hashedname eq lc( $ownername || '' );
}


sub optout {
	my $bit = 0x01;
	for ( shift->{flags} ||= 0 ) {
		return $_ & $bit unless scalar @_;
		my $set = $_ | $bit;
		$_ = (shift) ? $set : ( $set ^ $bit );
		return $_ & $bit;
	}
}


########################################


sub hashalgo {				## historical
	&algorithm;
}

sub nxtdname {				## inherited method inapplicable
	my $method = join '::', __PACKAGE__, 'nxtdname';
	confess "method '$method' undefined";
}


sub name2hash {
	my $hashalg    = shift;
	my $name       = lc( shift || '' );
	my $iterations = shift || 0;
	my $salt       = shift || '';

	my $arglist = $digest{$hashalg} || die 'unsupported hash algorithm';
	my ( $object, @argument ) = @$arglist;
	my $hash = $object->new(@argument);

	my $wirename = new Net::DNS::DomainName($name)->encode;
	$iterations++;

	while ( $iterations-- > 0 ) {
		$hash->add($wirename);
		$hash->add($salt);
		$wirename = $hash->digest;
	}

	my $base32hex = MIME::Base32::encode( $wirename, '' );	# [0-9 A-V]	per RFC4648, 7.
	return lc $base32hex;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name NSEC3 algorithm flags iterations salt hnxtname');

=head1 DESCRIPTION

Class for DNSSEC NSEC3 resource records.

The NSEC3 Resource Record (RR) provides authenticated denial of
existence for DNS Resource Record Sets.

The NSEC3 RR lists RR types present at the original owner name of the
NSEC3 RR.  It includes the next hashed owner name in the hash order
of the zone.  The complete set of NSEC3 RRs in a zone indicates which
RRSets exist for the original owner name of the RR and form a chain
of hashed owner names in the zone.

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 algorithm

    $algorithm = $rr->algorithm;
    $rr->algorithm( $algorithm );

The Hash Algorithm field is represented as an unsigned decimal
integer.  The value has a maximum of 255.

algorithm() may also be invoked as a class method or simple function
to perform mnemonic and numeric code translation.

=head2 flags

    $flags = $rr->flags;
    $rr->flags( $flags );

The Flags field is represented as an unsigned decimal integer.
The value has a maximum value of 255. 

=head2 iterations

    $iterations = $rr->iterations;
    $rr->iterations( $iterations );

The Iterations field is represented as an unsigned decimal
integer.  The value is between 0 and 65535, inclusive. 

=head2 salt

    $salt = $rr->salt;
    $rr->salt( $salt );

The Salt field is represented as a contiguous sequence of hexadecimal
digits. A "-" (unquoted) is used in string format to indicate that the
salt field is absent. 

=head2 saltbin

    $saltbin = $rr->saltbin;
    $rr->saltbin( $saltbin );

The Salt field as a sequence of octets. 

=head2 hnxtname

    $hnxtname = $rr->hnxtname;
    $rr->hnxtname( $hnxtname );

The Next Hashed Owner Name field points to the next node that has
authoritative data or contains a delegation point NS RRset.

=head2 typelist

    @typelist = $rr->typelist;
    $typelist = $rr->typelist;
    $rr->typelist( @typelist );

The Type List identifies the RRset types that exist at the NSEC RR
owner name.  When called in scalar context, the list is interpolated
into a string.

=head2 covered, matched

    print "covered" if $rr->covered{'example.foo'}

covered() returns a nonzero value when the the domain name provided as argument
is covered as defined in the NSEC3 specification:

   To cover:  An NSEC3 RR is said to "cover" a name if the hash of the
      name or "next closer" name falls between the owner name and the
      next hashed owner name of the NSEC3.  In other words, if it proves
      the nonexistence of the name, either directly or by proving the
      nonexistence of an ancestor of the name.


Similarly matched() returns a nonzero value when the domainname in the argument
matches as defined in the NSEC3 specification:

   To match: An NSEC3 RR is said to "match" a name if the owner name
      of the NSEC3 RR is the same as the hashed owner name of that
      name.

=head2 optout

    $rr->optout(0);
    $rr->optout(1);

    if ( $rr->optout ) {
	...
    }

Boolean Opt Out flag.


=head1 COPYRIGHT

Copyright (c)2007,2008 NLnet Labs.  Author Olaf M. Kolkman

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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, RFC5155

L<Hash Algorithms|http://www.iana.org/assignments/dnssec-nsec3-parameters>

=cut
