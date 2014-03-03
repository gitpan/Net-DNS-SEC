# $Id: 53-DS-GOST.t 1137 2013-12-10 14:48:08Z willem $

use strict;

BEGIN {
	use Test::More;

	plan skip_all => 'optional Digest::GOST not installed'
			unless eval { require Digest::GOST; };

	plan tests => 5;

	use_ok('Net::DNS::SEC');
	use_ok('Digest::GOST');
}


# Simple known-answer tests based upon the examples given in RFC5933, section 4.1

my $dnskey = Net::DNS::RR->new(
	'example.net. 86400   DNSKEY  257 3 12 (
					LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScO
					gEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroF
					SRGR7ZYcx+YIQw==
					) ; key id = 40692'
	);

my $ds = Net::DNS::RR->new(
	'example.net. 3600 IN DS 40692 12 3 (
			22261A8B0E0D799183E35E24E2AD6BB58533CBA7E3B14D659E9CA09B
			2071398F )'
	);


my $test = create Net::DNS::RR::DS(
	$dnskey,
	digtype => 'GOST',
	ttl	=> 3600
	);

is( $test->string, $ds->string, 'created DS matches RFC5933 example DS' );

ok( $test->verify($dnskey), 'created DS verifies RFC5933 example DNSKEY' );

ok( $ds->verify($dnskey), 'RFC5933 example DS verifies DNSKEY' );

$test->print;

__END__

