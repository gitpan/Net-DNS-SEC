package Net::DNS::RR::RRSIG;

#
# $Id: RRSIG.pm 1179 2014-03-19 21:46:58Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1179 $)[1];


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

use Net::DNS::Parameters;

eval { require Crypt::OpenSSL::RSA };	## optional for simple Net::DNS RR
eval { require Crypt::OpenSSL::DSA };
eval { require Crypt::OpenSSL::Bignum };
eval { require Digest::SHA };
eval { require Net::DNS::SEC::Private };

my $debug = 0;


sub decode_rdata {			## decode rdata from wire-format octet string
	my $self = shift;
	my ( $data, $offset ) = @_;

	my $limit = $offset + $self->{rdlength};
	my @field = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag);
	@{$self}{@field} = unpack "\@$offset n C2 N3 n", $$data;
	( $self->{signame}, $offset ) = decode Net::DNS::DomainName( $data, $offset + 18 );
	$self->{sigbin} = substr $$data, $offset, $limit - $offset;
}


sub encode_rdata {			## encode rdata as wire-format octet string
	my $self = shift;

	my $signame = $self->{signame} || return '';

	my @field = qw(typecovered algorithm labels orgttl sigexpiration siginception keytag);
	pack 'n C2 N3 n a* a*', @{$self}{@field}, $signame->encode(0), $self->sigbin;
}


sub format_rdata {			## format rdata portion of RR string.
	my $self = shift;

	return '' unless exists $self->{signame};
	my $line1 = join ' ', map $self->$_, qw(typecovered algorithm labels orgttl);
	my $line2 = join ' ', map $self->$_, qw(sigexpiration siginception keytag);
	my $signame = $self->{signame}->string;
	my $base64  = encode_base64 $self->sigbin;
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
	_time2string( $self->{sigexpiration} ) if defined wantarray;
}

sub siginception {
	my $self = shift;
	$self->{siginception} = _string2time(shift) if scalar @_;
	_time2string( $self->{siginception} ) if defined wantarray;
}


sub keytag {
	my $self = shift;

	$self->{keytag} = 0 + shift if scalar @_;
	return $self->{keytag} || 0;
}


sub signame {
	my $self = shift;

	$self->{signame} = new Net::DNS::DomainName(shift) if scalar @_;
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

	$self->{vrfyerrstr} = "---- Unknown Error Condition ------";
	if ($debug) {
		print "\n ------------------------------- RRSIG DEBUG ------------------";
		print "\n  Reference:\t", ref($dataref);
		print "\n  RRSIG:\t",	  $self->string;
		if ($rrarray_verify) {
			print "\n  DATA:\t\t", $_->string for @{$dataref};
		}
		print "\n  KEY:\t\t", $keyrr->string;
		print "\n --------------------------------------------------------------\n";
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

	my $signature = $self->sigbin;
	my $verified = $self->_VerifySig( $sigdata, $signature, $keyrr ) || return 0;

	# time to do some time checking.
	my $t = time;

	if ( _ordered( $self->{sigexpiration}, $t ) ) {
		$self->{vrfyerrstr} = join ' ', 'Signature expired at', $self->sigexpiration;
		return 0;
	} elsif ( _ordered( $t, $self->{siginception} ) ) {
		$self->{vrfyerrstr} = join ' ', 'Signature valid from', $self->siginception;
		return 0;
	}
	$self->{vrfyerrstr} = 'No Error';
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
	# See RFC4034 section 6 on how this string is constructed

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
	print "preamble:\t", unpack( 'H*', $sigdata ) if $debug;

	unless ( ref($rawdata) ) {				# SIG0 case
		print "\nSIG0 processing\nrawdata:\t", unpack( "H*", $rawdata ), "\n" if $debug;
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
	return $self->_CreateDSA(@_) if $DSA{$algorithm};

	croak "Algorithm $algorithm not supported";
}


sub _VerifySig {
	my $self = shift;

	my $algorithm = $self->algorithm;

	return $self->_VerifyRSA(@_) if $RSA{$algorithm};
	return $self->_VerifyDSA(@_) if $DSA{$algorithm};

	$self->{vrfyerrstr} = "Algorithm $algorithm not supported";
	return 0;
}


sub _CreateRSA {
	my ( $self, $sigdata, $private ) = @_;

	my $hash = $RSA{$private->algorithm} || croak 'private key not RSA';

	eval {
		my $private_rsa = $private->privatekey;
		$private_rsa->use_pkcs1_oaep_padding;
		$private_rsa->$hash;
		$self->sigbin( $private_rsa->sign($sigdata) );
	} || croak "RSA Signature generation failed\n\t$@";
}


sub _VerifyRSA {
	my ( $self, $sigdata, $signature, $keyrr ) = @_;

	# Implementation using Crypt::OpenSSL::RSA

	print "\nRSA verification called with key:\n\t", $keyrr->string,
			"\nsig:\n\t", $self->string, "\nsigdata:\n\t", unpack( 'H*', $sigdata ), "\n"
			if $debug;

	#RFC 2537 sect 2
	my ( $exponent, $modulus );
	if ( my $explength = unpack( 'C', my $keybin = $keyrr->keybin ) ) {
		( $exponent, $modulus ) = unpack( "x a$explength a*", $keybin );
	} else {
		$explength = unpack( 'xn', $keybin );
		( $exponent, $modulus ) = unpack( "x3 a$explength a*", $keybin );
	}

	my $bn_modulus	= Crypt::OpenSSL::Bignum->new_from_bin($modulus);
	my $bn_exponent = Crypt::OpenSSL::Bignum->new_from_bin($exponent);

	my $rsa_pub = Crypt::OpenSSL::RSA->new_key_from_parameters( $bn_modulus, $bn_exponent );
	die "Could not load public key" unless $rsa_pub;

	my $hash = $RSA{$self->algorithm};
	$rsa_pub->use_pkcs1_oaep_padding;
	$rsa_pub->$hash;

	if ( eval { $rsa_pub->verify( $sigdata, $signature ); } ) {
		$self->{vrfyerrstr} = "RSA Verification successful";
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 1;

	} elsif ( my $error = $@ ) {
		$self->{vrfyerrstr} = "RSA Verification error: $error";

	} else {
		$self->{vrfyerrstr} = "RSA Verification failed";
	}

	print "\n", $self->{vrfyerrstr}, "\n" if $debug;
	return 0;
}


sub _CreateDSA {
	my ( $self, $sigdata, $private ) = @_;

	my ( $object, @param ) = @{$DSA{$private->algorithm}};	# digest sig data
	croak 'private key not DSA' unless $object;
	my $hash = $object->new(@param);
	$hash->add($sigdata);

	my $private_dsa = $private->privatekey;
	if ( my $sig_obj = $private_dsa->do_sign( $hash->digest ) ) {

		# See RFC 2535 for the content of the SIG
		my $T = ( length( $private_dsa->get_g ) - 64 ) / 8;
		my $R = $sig_obj->get_r;
		my $S = $sig_obj->get_s;

		# both the R and S parameters need to be 20 octets:
		my $Rpad = 20 - length($R);
		my $Spad = 20 - length($S);
		$self->sigbin( pack "C x$Rpad a* x$Spad a*", $T, $R, $S );

	} else {
		croak "DSA Signature generation failed";
	}
}


sub _VerifyDSA {
	my ( $self, $sigdata, $signature, $keyrr ) = @_;

	# Implementation using Crypt::OpenSSL

	print "\nDSA verification called with key:\n", $keyrr->string, " and sig:\n", $self->string, "\n" if $debug;

	my ( $object, @param ) = @{$DSA{$self->algorithm}};	# digest sig data
	my $hash = $object->new(@param);
	$hash->add($sigdata);
	my $sighash = $hash->digest;

	# RFC3279  section 2.3.2
	# (...)
	# The DSA public key MUST be ASN.1 DER encoded as an INTEGER; this
	# encoding shall be used as the contents (i.e., the value) of the
	# subjectPublicKey component (a BIT STRING) of the
	# SubjectPublicKeyInfo data element.
	# (...)

	my $t = unpack 'C', $keyrr->keybin;

	my $size = $t * 8 + 64;
	my ( $q, $p, $g, $pubkey ) = unpack "x a20 a$size a$size a$size", $keyrr->keybin;

	my $dsa_pub = Crypt::OpenSSL::DSA->new();
	$dsa_pub->set_q($q);
	$dsa_pub->set_g($g);
	$dsa_pub->set_p($p);
	$dsa_pub->set_pub_key($pubkey);

	my ( $r, $s ) = unpack 'x a20 a20', $self->sigbin;

	my $DSAsig = Crypt::OpenSSL::DSA::Signature->new();
	$DSAsig->set_r($r);
	$DSAsig->set_s($s);

	if ( my $retval = eval { $dsa_pub->do_verify( $sighash, $DSAsig ); } ) {
		croak 'Error in DSA do_verify' if $retval == -1;    # fix for DSA < 0.14
		$self->{vrfyerrstr} = "DSA Verification successful";
		print "\n", $self->{vrfyerrstr}, "\n" if $debug;
		return 1;

	} elsif ( my $error = $@ ) {
		$self->{vrfyerrstr} = "DSA Verification error: $error";

	} else {
		$self->{vrfyerrstr} = "DSA Verification failed";
	}

	print "\n", $self->{vrfyerrstr}, "\n" if $debug;
	return 0;
}
 


1;
__END__


=head1 SYNOPSIS

    use Net::DNS;
    $rr = new Net::DNS::RR('name RRSIG typecovered algorithm labels
				orgttl sigexpiration siginception
				keytag signame signature');

    $rrsig = create Net::DNS::RR::RRSIG( \@rrset, $keypath,
					sigin => 20130701010101
					);

    $sigrr->verify( \@rrset, $keyrr ) || croak $sigrr->vrfyerrstr;

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
    $inception = $rr->siginception;

The signature expiration and inception fields specify a validity
time interval for the signature.

The value may be specified by a string with format 'yyyymmddhhmmss'
or a Perl time() value.


=head2 keytag

    $keytag = $rr->keytag;
    $rr->keytag( $keytag );

The keytag field contains the key tag value of the DNSKEY RR that
validates this signature.

=head2 signame

    $signame = $rr->signame;
    $rr->signame( $signame );

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

    $keypath = '/home/olaf/keys/Kbla.foo.+001+60114.private';

    $sigrr = create Net::DNS::RR::RRSIG( \@datarrset, $keypath );

    $sigrr = create Net::DNS::RR::RRSIG( \@datarrset, $keypath,
					sigin => 20130701010101
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
containing the private key as generated with dnssec-keygen, a program
that comes with the ISC BIND distribution.

The optional remaining arguments consist of ( name => value ) pairs
as follows:
	sigin  => 20130701010101,	# signature inception
	sigex  => 20130731010101,	# signature expiration
	sigval => 1.5,			# signature validity
	ttl    => 3600			# TTL

The sigin and sigex values may be specified as Perl time values or as
a string with the format 'yyyymmddhhmmss'. The default for sigin is
the time of signing. 

The sigval argument specifies the signature validity window in days
( sigex = sigin+sigval ).  Sigval wins if sigex is also specified.

By default the signature is valid for 30 days.

By default the TTL matches the RRSet that is presented for signing.

Notes: 

=over 4

=item *

Do not change the name of the file generated by dnssec-keygen, the
create method uses the filename as generated by dnssec-keygen to
determine the keyowner, algorithm and the keyid (keytag).

=item *

Only RSA signatures (algorithms 1,5,7,8 and 10) and DSA signatures 
(algorithms 3 and 6) have been implemented.

=back

=head2 verify and vrfyerrstr

    $sigrr->verify( $dataref, $keyrr ) || croak $sigrr->vrfyerrstr;
    $sigrr->verify( $dataref, [$keyrr, $keyrr2, $keyrr3] ) || 
		croak $sigrr->vrfyerrstr;

$dataref contains a reference to an array of RR objects and the
method verifies the RRset against the signature contained in the
$sigrr object itself using the public key in $keyrr.

The second argument can either be a Net::DNS::RR::KEYRR object or a
reference to an array of such objects. Verification will return
successful as soon as one of the keys in the array leads to positive
validation.

Returns 0 on error and sets $sig->vrfyerrstr

=head2 Example

    print $sigrr->vrfyerrstr unless $sigrr->verify( $rrset, $keyrr );

=head1 Remarks

The code is not optimized for speed.
It is probably not suitable to be used for signing large zones.


=head1 TODO

If this code is still around in 2100 (not a leapyear) you will need
to check for proper handling of times ...


=head1 ACKNOWLEDGMENTS

Andy Vaskys (Network Associates Laboratories) supplied the code for
handling RSA with SHA1 (Algorithm 5).

T.J. Mather, <tjmather@tjmather.com>, the Crypt::OpenSSL::DSA
maintainer, for his quick responses to bug report and feature
requests.

=cut


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

L<perl>, L<Net::DNS>, L<Net::DNS::RR>, L<Net::DNS::SEC>, RFC4034, RFC3755,
L<Crypt::OpenSSL::DSA>, L<Crypt::OpenSSL::RSA>

L<Algorithm Numbers|http://www.iana.org/assignments/dns-sec-alg-numbers>

=cut
