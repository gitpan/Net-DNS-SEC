package Net::DNS::RR::RRSIG;

#
# $Id: RRSIG.pm 1289 2015-01-05 10:08:59Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1289 $)[1];


use strict;
use base qw(Net::DNS::RR);

=head1 NAME

Net::DNS::RR::RRSIG - DNS RRSIG resource record

=cut


use integer;

use warnings;
use Carp;
use MIME::Base64;
use Time::Local;

use constant UTIL => eval { require Scalar::Util; } || 0;

use Net::DNS::Parameters;

eval { require Net::DNS::SEC::Private };

my $debug = 0;

BEGIN {
	eval { require Crypt::OpenSSL::RSA };
	eval { require Crypt::OpenSSL::Bignum };
	eval { require Digest::SHA };

	use constant DSA => eval { require Crypt::OpenSSL::DSA } || 0;
	use constant EC	 => eval { require Crypt::OpenSSL::EC }	 || 0;
	use constant ECDSA => EC && eval { require Crypt::OpenSSL::ECDSA }   || 0;
	use constant GOST  => EC && eval { require Digest::GOST::CryptoPro } || 0;
}


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	my @field = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag);
	@{$self}{@field} = unpack "\@$offset n C2 N3 n", $$data;
	( $self->{signame}, $offset ) = decode Net::DNS::DomainName2535( $data, $offset + 18 );
	$self->{sigbin} = substr $$data, $offset, $limit - $offset;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $sigbin = $self->sigbin || return '';
	my @field = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag);
	pack 'n C2 N3 n a* a*', @{$self}{@field}, $self->{signame}->encode, $sigbin;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	my $base64 = encode_base64 $self->sigbin || return '';
	my $line1 = join ' ', map $self->$_, qw(typecovered algorithm labels orgttl);
	my $line2 = join ' ', map $self->$_, qw(sigexpiration siginception keytag);
	my $signame = $self->{signame}->string;
	chomp $base64;
	return "$line1 (\n$line2 $signame\n$base64 )";
}


sub parse_rdata {			## populate RR from rdata in argument list
	my $self = shift;

	my @attribute = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag signame);
	$self->$_( scalar @_ ? shift : () ) for @attribute;
	$self->signature(@_);
}


my %RSA = (
	'1'  => 'use_md5_hash',
	'5'  => 'use_sha1_hash',
	'7'  => 'use_sha1_hash',
	'8'  => 'use_sha256_hash',
	'10' => 'use_sha512_hash',
	);

my %DSA = (
	'3' => ['Digest::SHA'],
	'6' => ['Digest::SHA'],
	);

my %GOST = ( '12' => ['Digest::GOST::CryptoPro'] );

my %ECDSA = (
	'13' => ['Digest::SHA', 256],
	'14' => ['Digest::SHA', 384],
	);


#
# source: http://www.iana.org/assignments/dns-sec-alg-numbers
#
{
	my @algbyname = (		## Reserved	=> 0,	# [RFC4034][RFC4398]
		'RSAMD5'	     => 1,			# [RFC3110][RFC4034]
		'DH'		     => 2,			# [RFC2539]
		'DSA'		     => 3,			# [RFC3755][RFC2536]
					## Reserved	=> 4,	# [RFC6725]
		'RSASHA1'	     => 5,			# [RFC3110][RFC4034]
		'DSA-NSEC3-SHA1'     => 6,			# [RFC5155]
		'RSASHA1-NSEC3-SHA1' => 7,			# [RFC5155]
		'RSASHA256'	     => 8,			# [RFC5702]
					## Reserved	=> 9,	# [RFC6725]
		'RSASHA512'	     => 10,			# [RFC5702]
					## Reserved	=> 11,	# [RFC6725]
		'ECC-GOST'	     => 12,			# [RFC5933]
		'ECDSAP256SHA256'    => 13,			# [RFC6605]
		'ECDSAP384SHA384'    => 14,			# [RFC6605]

		'INDIRECT'   => 252,				# [RFC4034]
		'PRIVATEDNS' => 253,				# [RFC4034]
		'PRIVATEOID' => 254,				# [RFC4034]
					## Reserved	=> 255,	# [RFC4034]
		);

	my %algbyval = reverse @algbyname;

	my @algbynum = map { ( $_, 0 + $_ ) } keys %algbyval;	# accept algorithm number

	my %algbyname = map { s /[^A-Za-z0-9]//g; $_ } @algbyname, @algbynum;


	sub algbyname {
		my $name = shift;
		my $key	 = uc $name;				# synthetic key
		$key =~ s /[^A-Z0-9]//g;			# strip non-alphanumerics
		return $algbyname{$key} || croak "unknown algorithm $name";
	}

	sub algbyval {
		my $value = shift;
		return $algbyval{$value} || $value;
	}
}


sub typecovered {
	my $self = shift;
	$self->{typecovered} = typebyname(shift) if scalar @_;
	return typebyval( $self->{typecovered} );
}


sub algorithm {
	my ( $self, $arg ) = @_;

	unless ( ref($self) ) {		## class method or simple function
		my $argn = pop || croak 'undefined argument';
		return $argn =~ /[^0-9]/ ? algbyname($argn) : algbyval($argn);
	}

	return $self->{algorithm} unless defined $arg;
	return algbyval( $self->{algorithm} ) if $arg =~ /MNEMONIC/i;
	return $self->{algorithm} = algbyname($arg);
}


sub labels {
	my $self = shift;

	$self->{labels} = 0 + shift if scalar @_;
	return $self->{labels} || 0;
}


sub orgttl {
	my $self = shift;

	$self->{orgttl} = 0 + shift if scalar @_;
	return $self->{orgttl} || 0;
}


sub sigexpiration {
	my $self = shift;
	$self->{sigexpiration} = _string2time(shift) if scalar @_;
	return unless defined wantarray;
	my $time = $self->{sigexpiration};
	return UTIL ? Scalar::Util::dualvar( $time, _time2string($time) ) : _time2string($time);
}

sub siginception {
	my $self = shift;
	$self->{siginception} = _string2time(shift) if scalar @_;
	return unless defined wantarray;
	my $time = $self->{siginception};
	return UTIL ? Scalar::Util::dualvar( $time, _time2string($time) ) : _time2string($time);
}


sub keytag {
	my $self = shift;

	$self->{keytag} = 0 + shift if scalar @_;
	return $self->{keytag} || 0;
}


sub signame {
	my $self = shift;

	$self->{signame} = new Net::DNS::DomainName2535(shift) if scalar @_;
	$self->{signame}->name if defined wantarray;
}


sub signature {
	my $self = shift;

	$self->sigbin( decode_base64( join '', @_ ) ) if scalar @_;
	encode_base64( $self->sigbin, '' ) if defined wantarray;
}

sub sig { &signature; }


sub sigbin {
	my $self = shift;

	$self->{sigbin} = shift if scalar @_;
	$self->{sigbin} || "";
}


sub create {
	my ( $class, $datarrset, $priv_key, %args ) = @_;

	my $private = ref($priv_key) ? $priv_key : Net::DNS::SEC::Private->new($priv_key);
	croak 'Unable to parse private key' unless ref($private) eq 'Net::DNS::SEC::Private';

	croak '$datarrset argument is not a reference to an array' unless ref($datarrset) =~ /ARRAY/;

	my $RR = $datarrset->[0] || {};

	croak '$datarrset is not a reference to an array of RRs' unless ref($RR) =~ /Net::DNS::RR/;

	# All the TTLs need to be the same in the data RRset.
	my $ttl = $RR->ttl;
	my @ttl = grep $_->ttl != $ttl, @$datarrset;
	croak 'RRs in RRset have different TTLs' if scalar @ttl;

	my @label = grep $_ ne chr(42), $RR->{owner}->_wire;	# count labels

	my $self = new Net::DNS::RR(
		name	    => $RR->name,
		type	    => 'RRSIG',
		class	    => 'IN',
		ttl	    => defined $args{ttl} ? $args{ttl} : $ttl,
		typecovered => $RR->type,
		labels	    => scalar @label,
		orgttl	    => $ttl,
		siginception  => $args{sigin} || time(),
		sigexpiration => $args{sigex} || 0,
		algorithm     => $private->algorithm,
		keytag	      => $private->keytag,
		signame	      => $private->signame,
		);

	$args{sigval} ||= 30 unless $self->{sigexpiration};
	if ( $args{sigval} ) {
		my $sigin = $self->{siginception};
		my $sigval = eval { no integer; int( $args{sigval} * 86400 ) };
		$self->sigexpiration( $sigin + $sigval );
	}

	my $sigdata = $self->_CreateSigData($datarrset);
	$self->_CreateSig( $sigdata, $private );

	return $self;
}


sub verify {
	my ( $self, $dataref, $keyref ) = @_;

	# Reminder...

	# $dataref must be a reference to an array of RR objects.

	# $keyref is either a reference to an array of keys or a a key object.


	my $sigzero_verify = 0;
	my $packet_verify  = 0;
	my $rrarray_verify = 0;

	my $algorithm = $self->algorithm;
	my $keyrr;						# This will be used to store the key
								# against which we want to verify.

	print "Second argument is of class ", ref($keyref), "\n" if $debug;
	if ( ref($keyref) eq "ARRAY" ) {

		#  We will recurse for each key that matches algorithm and key-id
		#  we return when there is a successful verification.
		#  If not we'll continue so that we even survive key-id collision.
		#  The downside of this is that the error string only matches the
		#  last error.
		my @keyarray	= @{$keyref};
		my $errorstring = "";
		my $i		= 0;
		print "Iterating over " . @keyarray . " keys \n" if $debug;
		foreach my $keyrr (@keyarray) {
			$i++;
			unless ( $algorithm == $keyrr->algorithm ) {
				print "key $i: algorithm does not match\n" if $debug;
				$errorstring .= "key $i: algorithm does not match ";
				next;
			}
			unless ( $self->keytag == $keyrr->keytag ) {
				print "key $i: keytag does not match (", $keyrr->keytag, " ", $self->keytag, ")\n"
						if $debug;
				$errorstring .= "key $i: keytag does not match ";
				next;
			}

			my $result = $self->verify( $dataref, $keyrr );
			print "key $i:" . $self->{vrfyerrstr} if $debug;
			return $result if $result;
			$errorstring .= "key $i:" . $self->vrfyerrstr . " ";
		}

		$self->{vrfyerrstr} = $errorstring;
		return (0);

	} elsif (  ref($keyref) eq 'Net::DNS::RR::DNSKEY'
		|| ref($keyref) eq 'Net::DNS::RR::KEY' ) {	# we are liberal...

		# substitute and continue processing after this conditional
		$keyrr = $keyref;
		print "Validating using key with keytag: ", $keyrr->keytag, "\n" if $debug;

	} else {
		$self->{vrfyerrstr} = "You are trying to pass " . ref($keyref) . " data for a key";
		return (0);
	}

	print "Verifying data of class: ", ref($dataref), "\n" if $debug;
	$sigzero_verify = 1 unless ref($dataref);
	if ( !$sigzero_verify ) {
		if ( ref($dataref) eq "ARRAY" ) {

			if ( ref( $dataref->[0] ) and $dataref->[0]->isa('Net::DNS::RR') ) {
				$rrarray_verify = 1;
			} else {
				die "Trying to verify an array of " . ref( $dataref->[0] ) . "\n";
			}

		} elsif ( ref($dataref) and $dataref->isa("Net::DNS::Packet") ) {
			$packet_verify = 1;
			die "Trying to verify a packet using non-SIG0 signature" unless $self->{typecovered};

		} else {
			die "Do not know what kind of data this is: " . ref($dataref) . ")\n";
		}
	}

	$self->{vrfyerrstr} = '';
	if ($debug) {
		print "\n ---------------------- RRSIG DEBUG ----------------------------";
		print "\n  Reference:\t", ref($dataref);
		print "\n  RRSIG:\t",	  $self->string;
		if ($rrarray_verify) {
			print "\n  DATA:\t\t", $_->string for @{$dataref};
		}
		print "\n  KEY:\t\t", $keyrr->string;
		print "\n ---------------------------------------------------------------\n";
	}

	if ( !$sigzero_verify && !$packet_verify && $dataref->[0]->type ne $self->typecovered ) {
		$self->{vrfyerrstr} = join ' ', 'Cannot verify datatype', $dataref->[0]->type,
				'with key intended for', $self->typecovered, 'verification';
		return 0;
	}

	if ( $rrarray_verify && !$dataref->[0]->type eq "RRSIG" ) {

		# if [0] has type RRSIG the whole RRset is type RRSIG.
		# There are no SIGs over SIG RRsets
		$self->{vrfyerrstr} = "RRSIGs over RRSIGs???\nThis is not possible.\n";
		return 0;
	}

	if ( $algorithm != $keyrr->algorithm ) {
		$self->{vrfyerrstr} = join ' ',
				'signature created using algorithm',   $algorithm,
				'can not be verified using algorithm', $keyrr->algorithm;
		return 0;
	}


	if ($packet_verify) {

		my $clone = bless {%$dataref}, ref($dataref);	# shallow clone
		my @addnl = grep $_ != $self, @{$dataref->{additional}};
		$clone->{additional} = \@addnl;			# without SIG RR

		my @part = qw(question answer authority additional);
		my @size = map scalar( @{$clone->{$_}} ), @part;
		$dataref = pack 'n6', $clone->{ident}, $clone->{status}, @size;
		foreach my $rr ( map @{$clone->{$_}}, @part ) {
			$dataref .= $rr->canonical;
		}
	}


	# The data that is to be verified
	my $sigdata = $self->_CreateSigData($dataref);

	my $verified = $self->_VerifySig( $sigdata, $keyrr ) || return 0;

	# time to do some time checking.
	my $t = time;

	if ( _ordered( $self->{sigexpiration}, $t ) ) {
		$self->{vrfyerrstr} = join ' ', 'Signature expired at', $self->sigexpiration;
		return 0;
	} elsif ( _ordered( $t, $self->{siginception} ) ) {
		$self->{vrfyerrstr} = join ' ', 'Signature valid from', $self->siginception;
		return 0;
	}

	return 1;
}								#END verify


sub vrfyerrstr {
	my $self = shift;
	$self->{vrfyerrstr} || '';
}


########################################

sub _ordered($$) {			## irreflexive 32-bit partial ordering
	use integer;
	my ( $a, $b ) = @_;

	return defined $b unless defined $a;			# ( undef, any )
	return 0 unless defined $b;				# ( any, undef )

	# unwise to assume 32-bit arithmetic, or that integer overflow goes unpunished
	if ( $a < 0 ) {						# translate $a<0 region
		$a = ( $a ^ 0x80000000 ) & 0xFFFFFFFF;		#  0	 <= $a < 2**31
		$b = ( $b ^ 0x80000000 ) & 0xFFFFFFFF;		# -2**31 <= $b < 2**32
	}

	return $a < $b ? ( $a > ( $b - 0x80000000 ) ) : ( $b < ( $a - 0x80000000 ) );
}


my $y1998 = timegm( 0, 0, 0, 1, 0, 1998 );
my $y2026 = timegm( 0, 0, 0, 1, 0, 2026 );
my $y2082 = $y2026 << 1;
my $y2054 = $y2082 - $y1998;

sub _string2time {			## parse time specification string
	my $arg = shift;
	croak 'undefined time' unless defined $arg;
	return int($arg) if length($arg) < 12;
	my ( $y, $m, @dhms ) = unpack 'a4 a2 a2 a2 a2 a2', $arg . '00';
	unless ( $arg gt '20380119031407' ) {			# calendar folding
		return timegm( reverse(@dhms), $m - 1, $y ) if $y < 2026;
		return timegm( reverse(@dhms), $m - 1, $y - 56 ) + $y2026;
	} elsif ( $y > 2082 ) {
		my $z = timegm( reverse(@dhms), $m - 1, $y - 84 );    # expunge 29 Feb 2100
		return $z < 1456790400 ? $z + $y2054 : $z + $y2054 - 86400;
	}
	return ( timegm( reverse(@dhms), $m - 1, $y - 56 ) + $y2054 ) - $y1998;
}


sub _time2string {			## format time specification string
	my $arg = shift;
	croak 'undefined time' unless defined $arg;
	unless ( $arg < 0 ) {
		my ( $yy, $mm, @dhms ) = reverse( ( gmtime $arg )[0 .. 5] );
		return sprintf '%d%02d%02d%02d%02d%02d', $yy + 1900, $mm + 1, @dhms;
	} elsif ( $arg > $y2082 ) {
		$arg += 86400 unless $arg < $y2054 + 1456704000;      # expunge 29 Feb 2100
		my ( $yy, $mm, @dhms ) = reverse( ( gmtime( $arg - $y2054 ) )[0 .. 5] );
		return sprintf '%d%02d%02d%02d%02d%02d', $yy + 1984, $mm + 1, @dhms;
	}
	my ( $yy, $mm, @dhms ) = reverse( ( gmtime( $arg - $y2026 ) )[0 .. 5] );
	return sprintf '%d%02d%02d%02d%02d%02d', $yy + 1956, $mm + 1, @dhms;
}


sub _CreateSigData {
	my ( $self, $rawdata ) = @_;

	# This method creates the data string that will be signed.
	# See RFC4034(6) and RFC6840(5.1) on how this string is constructed

	# This method is called by the method that creates a signature
	# and by the method that verifies the signature. It is assumed
	# that the creation method has checked that all the TTLs are
	# the same for the dataref and that sig->orgttl has been set
	# to the TTL of the data. This method will set the datarr->ttl
	# to the sig->orgttl for all the RR in the dataref.

	print "_CreateSigData\n" if $debug;

	$self->{typecovered} = 0 unless ref($rawdata);		# SIG0

	my @field = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag);
	my $sigdata = pack 'n C2 N3 n a*', @{$self}{@field}, $self->{signame}->encode;
	print "\npreamble\t", unpack( 'H*', $sigdata ), "\n" if $debug;

	unless ( ref($rawdata) ) {				# SIG0 case
		print "\nSIG0 processing\nrawdata\t", unpack( 'H100', $rawdata ), "\n" if $debug;
		return join '', $sigdata, $rawdata;
	}

	my $owner = $self->{owner};				# create wildcard domain name
	my $limit = $self->{labels};
	my @label = $owner->_wire;
	shift @label while scalar @label > $limit;
	my $wild = bless {label => \@label}, ref($owner);	# DIY to avoid wrecking name cache
	my $suffix = $wild->encode(0);
	unshift @label, chr(42);				# asterisk

	my @RR	  = map bless( {%$_}, ref($_) ), @$rawdata;	# shallow RR clone
	my $RR	  = $RR[0];
	my $class = $RR->class;
	my $type  = $RR->type;

	my $ttl = $self->orgttl;
	my %table;
	foreach my $RR (@RR) {
		my $ident = $self->{owner}->encode(0);
		my $match = substr $ident, -length($suffix);
		croak 'RRs in RRset have different NAMEs' if $match ne $suffix;
		croak 'RRs in RRset have different TYPEs' if $type ne $RR->type;
		croak 'RRs in RRset have different CLASS' if $class ne $RR->class;
		$RR->ttl($ttl);					# reset TTL

		my $offset = 10 + length($suffix);		# RDATA offset
		if ( $ident ne $match ) {
			$RR->{owner} = $wild;
			$offset += 2;
			print "\nsubstituting wildcard name: ", $RR->name if $debug;
		}

		# For sorting we create a hash table of canonical data keyed on RDATA
		my $canonical = $RR->canonical;
		$table{substr $canonical, $offset} = $canonical;
	}

	$sigdata = join '', $sigdata, map $table{$_}, sort keys %table;

	if ($debug) {
		my $i = 0;
		foreach my $rdata ( sort keys %table ) {
			print "\n>>> ", $i++, "\tRDATA:\t", unpack 'H*', $rdata;
			print "\nRR: ", unpack( 'H*', $table{$rdata} ), "\n";
		}
		print "\n sigdata:\t", unpack( 'H*', $sigdata ), "\n";
	}

	return $sigdata;
}


########################################

sub _CreateSig {
	my $self = shift;

	my $algorithm = $self->algorithm;

	return $self->_CreateRSA(@_) if $RSA{$algorithm};
	return $self->_CreateDSA(@_) if DSA && $DSA{$algorithm};

	return $self->_CreateECDSA(@_) if ECDSA && $ECDSA{$algorithm};

	croak "Signature generation not supported for algorithm $algorithm";
}


sub _VerifySig {
	my $self = shift;

	my $algorithm = $self->algorithm;

	return $self->_VerifyRSA(@_) if $RSA{$algorithm};
	return $self->_VerifyDSA(@_) if DSA && $DSA{$algorithm};

	return $self->_VerifyECDSA(@_) if ECDSA && $ECDSA{$algorithm};
	return $self->_VerifyGOST(@_)  if GOST	&& $GOST{$algorithm};

	$self->{vrfyerrstr} = "Verification not supported for algorithm $algorithm";
	return 0;
}


sub _CreateRSA {
	my ( $self, $sigdata, $private ) = @_;

	my $hash = $RSA{$private->algorithm} || croak 'private key not RSA';

	eval {
		my @param = map Crypt::OpenSSL::Bignum->new_from_bin( decode_base64( $private->$_ ) ),
				qw(Modulus PublicExponent PrivateExponent
				Prime1 Prime2 Exponent1 Exponent2 Coefficient);
		my $rsa = Crypt::OpenSSL::RSA->new_key_from_parameters(@param);

		$rsa->use_pkcs1_oaep_padding;
		$rsa->$hash;
		$self->sigbin( $rsa->sign($sigdata) );
	} || carp "RSA signature generation failed\n\t$@";
}


sub _VerifyRSA {
	my ( $self, $sigdata, $keyrr ) = @_;

	# Implementation using Crypt::OpenSSL::RSA

	print "\n_VerifyRSA:\n", $self->string, "\nusing key:\n", $keyrr->string, "\n" if $debug;

	eval {
		my $keybin = $keyrr->keybin;			# public key
		my ( $exponent, $modulus );			# RFC 2537, section 2
		if ( my $explength = unpack( 'C', $keybin ) ) {
			( $exponent, $modulus ) = unpack( "x a$explength a*", $keybin );
		} else {
			$explength = unpack( 'xn', $keybin );
			( $exponent, $modulus ) = unpack( "x3 a$explength a*", $keybin );
		}

		my $bn_modulus	= Crypt::OpenSSL::Bignum->new_from_bin($modulus);
		my $bn_exponent = Crypt::OpenSSL::Bignum->new_from_bin($exponent);

		my $rsa = Crypt::OpenSSL::RSA->new_key_from_parameters( $bn_modulus, $bn_exponent );

		my $hash = $RSA{$self->algorithm};
		$rsa->use_pkcs1_oaep_padding;
		$rsa->$hash;

		$rsa->verify( $sigdata, $self->sigbin );
	} || do {
		$self->{vrfyerrstr} = "RSA Verification failed";
		$self->{vrfyerrstr} = "RSA verification error: $@" if $@;
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 0;
	};

	print "\nRSA verification successful\n" if $debug;
	return 1;
}


sub _CreateDSA {
	my ( $self, $sigdata, $private ) = @_;

	eval {
		my $algorithm = $private->algorithm;		# digest sigdata
		my ( $object, @param ) = @{$DSA{$algorithm}};
		croak 'private key not DSA' unless $object;
		my $hash = $object->new(@param);
		$hash->add($sigdata);

		my $dsa = Crypt::OpenSSL::DSA->new();		# private key
		$dsa->set_p( decode_base64 $private->prime );
		$dsa->set_q( decode_base64 $private->subprime );
		$dsa->set_g( decode_base64 $private->base );
		$dsa->set_priv_key( decode_base64 $private->private_value );

		my $dsasig = $dsa->do_sign( $hash->digest );

		# See RFC 2535 for the content of the SIG
		my $T = ( length( $dsa->get_g ) - 64 ) / 8;
		my $R = $dsasig->get_r;
		my $S = $dsasig->get_s;

		# both the R and S parameters need to be 20 octets:
		my $Rpad = 20 - length($R);
		my $Spad = 20 - length($S);
		$self->sigbin( pack "C x$Rpad a* x$Spad a*", $T, $R, $S );
	} || carp "DSA signature generation failed\n\t$@";
}


sub _VerifyDSA {
	my ( $self, $sigdata, $keyrr ) = @_;

	print "\n_VerifyDSA:\n", $self->string, "\nusing key:\n", $keyrr->string, "\n" if $debug;

	my $retval = eval {
		my $algorithm = $self->algorithm;		# digest sigdata
		my ( $object, @param ) = @{$DSA{$algorithm}};
		my $hash = $object->new(@param);
		$hash->add($sigdata);

		my $keybin = $keyrr->keybin;			# public key
		my $numlen = 64 + 8 * unpack( 'C', $keybin );
		my ( $q, $p, $g, $k ) = unpack "x a20 a$numlen a$numlen a$numlen", $keybin;

		my $dsa = Crypt::OpenSSL::DSA->new();
		$dsa->set_q($q);
		$dsa->set_g($g);
		$dsa->set_p($p);
		$dsa->set_pub_key($k);

		my $dsasig = Crypt::OpenSSL::DSA::Signature->new();
		my ( $r, $s ) = unpack 'x a20 a20', $self->sigbin;
		$dsasig->set_r($r);
		$dsasig->set_s($s);

		$dsa->do_verify( $hash->digest, $dsasig );
	} || do {
		$self->{vrfyerrstr} = "DSA verification failed";
		$self->{vrfyerrstr} = "DSA verification error: $@" if $@;
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 0;
	};

	croak 'Error in DSA_do_verify' unless $retval == 1;	# fix for DSA < 0.14
	print "\nDSA verification successful\n" if $debug;
	return 1;
}


BEGIN {
	use vars qw(%ECcurve);

	my %NIST_P256 = (		## FIPS 186-4, D.1.2.3
		p => 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
		a => 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc',    # -3 mod p
		b => '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
		x => '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
		y => '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
		n => 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
		);

	my %NIST_P384 = (		## FIPS 186-4, D.1.2.4
		p => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
		a => 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc',
		b => 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
		x => 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
		y => '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f',
		n => 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973',
		);

	my %GOST_R_34_10_2001_CryptoPro_A = (			# RFC4357
		a => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94',    # -3 mod p
		b => '00A6',					# 166
		p => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97',
		n => 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893',    # q
		x => '01',
		y => '8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14'
		);


	my $_curve = sub {
		return unless EC;

		my %param = @_;

		my $p = Crypt::OpenSSL::Bignum->new_from_hex( $param{p} );
		my $a = Crypt::OpenSSL::Bignum->new_from_hex( $param{a} );
		my $b = Crypt::OpenSSL::Bignum->new_from_hex( $param{b} );
		my $x = Crypt::OpenSSL::Bignum->new_from_hex( $param{x} );
		my $y = Crypt::OpenSSL::Bignum->new_from_hex( $param{y} );
		my $n = Crypt::OpenSSL::Bignum->new_from_hex( $param{n} );
		my $h = Crypt::OpenSSL::Bignum->one;

		my $ctx	   = Crypt::OpenSSL::Bignum::CTX->new();
		my $method = Crypt::OpenSSL::EC::EC_GFp_mont_method();
		my $group  = Crypt::OpenSSL::EC::EC_GROUP::new($method);
		$group->set_curve_GFp( $p, $a, $b, $ctx );	# y^2 = x^3 + a*x + b  mod p

		my $G = Crypt::OpenSSL::EC::EC_POINT::new($group);
		Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp( $group, $G, $x, $y, $ctx );
		$group->set_generator( $G, $n, $h );
		die 'bad curve' unless Crypt::OpenSSL::EC::EC_GROUP::check( $group, $ctx );
		return $group;
	};

	$ECcurve{12} = &$_curve(%GOST_R_34_10_2001_CryptoPro_A);
	$ECcurve{13} = &$_curve(%NIST_P256);
	$ECcurve{14} = &$_curve(%NIST_P384);
}


sub _CreateECDSA {
	my ( $self, $sigdata, $private ) = @_;

	eval {
		my $algorithm = $self->algorithm;
		my $group     = $ECcurve{$algorithm}->dup();	# precalculated curve

		my ( $object, @param ) = @{$ECDSA{$algorithm}}; # digest sigdata
		croak 'private key not ECDSA' unless $object;
		my $hash = $object->new(@param);
		$hash->add($sigdata);
		my $digest = $hash->digest;

		my $keybin = decode_base64( $private->PrivateKey );
		my $bignum = Crypt::OpenSSL::Bignum->new_from_bin($keybin);

		my $eckey = Crypt::OpenSSL::EC::EC_KEY::new();
		$eckey->set_group($group)	 || die;
		$eckey->set_private_key($bignum) || die;

		my $ecsig = Crypt::OpenSSL::ECDSA::ECDSA_do_sign( $digest, $eckey );
		my ( $r, $s ) = ( $ecsig->get_r, $ecsig->get_s );

		# both the r and s parameters need to be zero padded:
		my $size = length $digest;
		my $Rpad = $size - length $r;
		my $Spad = $size - length $s;
		$self->sigbin( pack "x$Rpad a* x$Spad a*", $r, $s );
	} || carp "ECDSA signature generation failed\n\t$@";
}


sub _VerifyECDSA {
	my ( $self, $sigdata, $keyrr ) = @_;

	# Implementation using Crypt::OpenSSL::ECDSA

	print "\n_VerifyECDSA:\n", $self->string, "\nusing key:\n", $keyrr->string, "\n" if $debug;

	my $retval = eval {
		my $algorithm = $self->algorithm;
		my $group     = $ECcurve{$algorithm}->dup();	# precalculated curve

		my ( $object, @param ) = @{$ECDSA{$algorithm}}; # digest sigdata
		my $hash = $object->new(@param);
		$hash->add($sigdata);
		my $digest = $hash->digest;

		my $keybin = $keyrr->keybin;			# public key
		my $keylen = length($keybin) >> 1;
		my ( $x, $y ) = map Crypt::OpenSSL::Bignum->new_from_bin($_), unpack "a$keylen a*", $keybin;
		my $key = Crypt::OpenSSL::EC::EC_POINT::new($group);
		my $ctx = Crypt::OpenSSL::Bignum::CTX->new();
		Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp( $group, $key, $x, $y, $ctx );

		my $eckey = Crypt::OpenSSL::EC::EC_KEY::new();
		$eckey->set_group($group)    || die;
		$eckey->set_public_key($key) || die;

		my $sigbin = $self->sigbin;			# signature
		my $siglen = length($sigbin) >> 1;
		my ( $r, $s ) = unpack( "a$siglen a*", $sigbin );

		my $dsasig = Crypt::OpenSSL::ECDSA::ECDSA_SIG->new();
		$dsasig->set_r($r);
		$dsasig->set_s($s);

		Crypt::OpenSSL::ECDSA::ECDSA_do_verify( $digest, $dsasig, $eckey );
	} || do {
		$self->{vrfyerrstr} = "ECDSA verification failed";
		$self->{vrfyerrstr} = "ECDSA verification error: $@" if $@;
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 0;
	};

	croak 'Error in ECDSA_do_verify' unless $retval == 1;
	print "\nECDSA verification successful\n" if $debug;
	return 1;
}


sub _VerifyGOST {
	my ( $self, $sigdata, $keyrr ) = @_;

	# Implementation (ab)using Crypt::OpenSSL::ECDSA

	print "\n_VerifyGOST:\n", $self->string, "\nusing key:\n", $keyrr->string, "\n" if $debug;

	my $retval = eval {
		my $algorithm = $self->algorithm;
		my $group     = $ECcurve{$algorithm}->dup();	# precalculated curve

		my $zeta = $self->sigbin;			# step 1	(nomenclature per RFC5832)
		my $size = length($zeta) >> 1;
		my ( $s, $r ) = unpack( "a$size a*", $zeta );

		my ( $object, @param ) = @{$GOST{$algorithm}};	# step 2
		my $hash = $object->new(@param);
		$hash->add($sigdata);
		my $H = reverse $hash->digest;

		my $ctx = Crypt::OpenSSL::Bignum::CTX->new();	# step 3
		my $q	= Crypt::OpenSSL::Bignum->zero;
		$group->get_order( $q, $ctx );
		my $alpha = Crypt::OpenSSL::Bignum->new_from_bin($H);
		my $e = $alpha->mod( $q, $ctx );    # Note: alpha can exceed but is never longer than q
		$e = Crypt::OpenSSL::Bignum->one if $e->is_zero;

		my $keybin = reverse $keyrr->keybin;		# public key
		my $keylen = length($keybin) >> 1;
		my ( $y, $x ) = map Crypt::OpenSSL::Bignum->new_from_bin($_), unpack "a$keylen a*", $keybin;
		my $Q = Crypt::OpenSSL::EC::EC_POINT::new($group);
		Crypt::OpenSSL::EC::EC_POINT::set_affine_coordinates_GFp( $group, $Q, $x, $y, $ctx );

		my $eckey = Crypt::OpenSSL::EC::EC_KEY::new();
		$eckey->set_group($group)  || die;
		$eckey->set_public_key($Q) || die;

		# algebraic transformation of ECC-GOST into equivalent ECDSA problem
		my $dsasig = Crypt::OpenSSL::ECDSA::ECDSA_SIG->new();
		$dsasig->set_r($r);
		$dsasig->set_s( $q->sub($e)->to_bin );

		my $m = $q->sub( Crypt::OpenSSL::Bignum->new_from_bin($s) )->mod( $q, $ctx );
		Crypt::OpenSSL::ECDSA::ECDSA_do_verify( $m->to_bin, $dsasig, $eckey );
	} || do {
		$self->{vrfyerrstr} = "EC-GOST verification failed";
		$self->{vrfyerrstr} = "EC-GOST verification error: $@" if $@;
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 0;
	};

	croak 'Error in ECDSA_do_verify' unless $retval == 1;
	print "\nECC-GOST verification successful\n" if $debug;
	return 1;
}


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name RRSIG typecovered algorithm labels
				orgttl sigexpiration siginception
				keytag signame signature');

    $sigrr = create Net::DNS::RR::RRSIG( \@rrset, $keypath,
					sigex => 20140731010101
					sigin => 20140701010101
					);

    $sigrr->verify( \@rrset, $keyrr ) || die $sigrr->vrfyerrstr;

=head1 DESCRIPTION

Class for DNS digital signature (RRSIG) resource records.

In addition to the regular methods inherited from Net::DNS::RR the
class contains a method to sign RRsets using private keys (create)
and a method for verifying signatures over RRsets (verify).

The RRSIG RR is an implementation of RFC4034. 
See L<Net::DNS::RR::SIG> for an implementation of SIG0 (RFC2931).

=head1 METHODS

The available methods are those inherited from the base class augmented
by the type-specific methods defined in this package.

Use of undocumented package features or direct access to internal data
structures is discouraged and could result in program termination or
other unpredictable behaviour.


=head2 typecovered

    $typecovered = $rr->typecovered;

The typecovered field identifies the type of the RRset that is
covered by this RRSIG record.

=head2 algorithm

    $algorithm = $rr->algorithm;

The algorithm number field identifies the cryptographic algorithm
used to create the signature.

algorithm() may also be invoked as a class method or simple function
to perform mnemonic and numeric code translation.

=head2 labels

    $labels = $rr->labels;
    $rr->labels( $labels );

The labels field specifies the number of labels in the original RRSIG
RR owner name.

=head2 orgttl

    $orgttl = $rr->orgttl;
    $rr->orgttl( $orgttl );

The original TTL field specifies the TTL of the covered RRset as it
appears in the authoritative zone.

=head2 sigexpiration and siginception time

    $expiration = $rr->sigexpiration;
    $expiration = $rr->sigexpiration( $value );

    $inception = $rr->siginception;
    $inception = $rr->siginception( $value );

The signature expiration and inception fields specify a validity
time interval for the signature.

The value may be specified by a string with format 'yyyymmddhhmmss'
or a Perl time() value.

Return values are dual-valued, providing either a string value or 
numerical Perl time() value.

=head2 keytag

    $keytag = $rr->keytag;
    $rr->keytag( $keytag );

The keytag field contains the key tag value of the DNSKEY RR that
validates this signature.

=head2 signame

    $signame = $rr->signame;

The signer name field value identifies the owner name of the DNSKEY
RR that a validator is supposed to use to validate this signature.

=head2 signature

    $signature = $rr->signature;

The Signature field contains the cryptographic signature that covers
the RRSIG RDATA (excluding the Signature field) and the RRset
specified by the RRSIG owner name, RRSIG class, and RRSIG type
covered fields.

=head2 sigbin

    $sigbin = $rr->sigbin;
    $rr->sigbin( $sigbin );

Binary representation of the cryptographic signature.

=head2 create

Create a signature over a RR set.

    use Net::DNS::SEC;

    $keypath = '/home/olaf/keys/Kbla.foo.+001+60114.private';

    $sigrr = create Net::DNS::RR::RRSIG( \@datarrset, $keypath );

    $sigrr = create Net::DNS::RR::RRSIG( \@datarrset, $keypath,
					sigex => 20140731010101
					sigin => 20140701010101
					);
    $sigrr->print;


    #Alternatively use Net::DNS::SEC::Private 

    $private = Net::DNS::SEC::Private->new($keypath);

    $sigrr= create Net::DNS::RR::RRSIG( \@datarrset, $private );


create() is an alternative constructor for a RRSIG RR object.  

This method returns an RRSIG with the signature over the datarrset
(an array of RRs) made with the private key stored in the key file.

The first argument is a reference to an array that contains the RRset
that needs to be signed.

The second argument is a string which specifies the path to a file
containing the private key as generated by dnssec-keygen.

The optional remaining arguments consist of ( name => value ) pairs
as follows:

	sigex  => 20140731010101,	# signature expiration
	sigin  => 20140701010101,	# signature inception
	sigval => 30,			# validity window (days)
	ttl    => 3600			# TTL

The sigin and sigex values may be specified as Perl time values or as
a string with the format 'yyyymmddhhmmss'. The default for sigin is
the time of signing. 

The sigval argument specifies the signature validity window in days
( sigex = sigin + sigval ).

By default the signature is valid for 30 days.

By default the TTL matches the RRset that is presented for signing.

=head2 verify

    $verify = $sigrr->verify( $dataref, $keyrr );
    $verify = $sigrr->verify( $dataref, [$keyrr, $keyrr2, $keyrr3] );

$dataref contains a reference to an array of RR objects and the
method verifies the RRset against the signature contained in the
$sigrr object itself using the public key in $keyrr.

The second argument can either be a Net::DNS::RR::KEYRR object or a
reference to an array of such objects. Verification will return
successful as soon as one of the keys in the array leads to positive
validation.

Returns 0 on error and sets $sig->vrfyerrstr

=head2 vrfyerrstr

    $verify = $sigrr->verify( $dataref, $keyrr );
    print $sigrr->vrfyerrstr unless $verify;

    $sigrr->verify( $dataref, $keyrr ) || die $sigrr->vrfyerrstr;

=head1 KEY GENERATION

Private key files and corresponding public DNSKEY records
are most conveniently generated using dnssec-keygen,
a program that comes with the ISC BIND distribution.

    dnssec-keygen -a 10 -b 2048 -f ksk	rsa.example.
    dnssec-keygen -a 10 -b 1024		rsa.example.

    dnssec-keygen -a 14	-f ksk	ecdsa.example.
    dnssec-keygen -a 14		ecdsa.example.

Do not change the name of the file generated by dnssec-keygen.
The create method uses the filename to determine the keyowner,
algorithm and the keyid (keytag).


=head1 REMARKS

The code is not optimized for speed.
It is probably not suitable to be used for signing large zones.

If this code is still around in 2100 (not a leapyear) you will need
to check for proper handling of times ...

=head1 ACKNOWLEDGMENTS

Andy Vaskys (Network Associates Laboratories) supplied the code for
handling RSA with SHA1 (Algorithm 5).

T.J. Mather, the Crypt::OpenSSL::DSA maintainer, for his quick
responses to bug report and feature requests.

Dick Franks added support for elliptic curve signatures.

Mike McCauley created the Crypt::OpenSSL::ECDSA perl extension module
specifically for this development.


=head1 COPYRIGHT

Copyright (c)2001-2005 RIPE NCC,   Olaf M. Kolkman 

Copyright (c)2007-2008 NLnet Labs, Olaf M. Kolkman 

Portions Copyright (c)2014 Dick Franks 


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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::SEC>,
RFC4034, RFC6840, RFC3755,
L<Crypt::OpenSSL::DSA>,
L<Crypt::OpenSSL::EC>,
L<Crypt::OpenSSL::ECDSA>,
L<Crypt::OpenSSL::RSA>

L<Algorithm Numbers|http://www.iana.org/assignments/dns-sec-alg-numbers>

L<BIND 9 Administrator Reference Manual|http://www.bind9.net/manuals>

=cut
