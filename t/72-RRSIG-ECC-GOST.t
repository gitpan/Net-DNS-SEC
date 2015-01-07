# $Id: 72-RRSIG-ECC-GOST.t 1293 2015-01-07 07:42:26Z willem $	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More;

	my @prerequisite = qw(
		Digest::GOST
		Digest::GOST::CryptoPro
		Crypt::OpenSSL::EC
		Crypt::OpenSSL::ECDSA
		Crypt::OpenSSL::Random
		);

	foreach my $package (@prerequisite) {
		plan skip_all => "optional $package not installed"
			unless eval "require $package";
	}

	plan tests => 11;

	use_ok('Net::DNS::SEC');

	use_ok('Digest::GOST::CryptoPro');
	use_ok('Crypt::OpenSSL::EC');
	use_ok('Crypt::OpenSSL::ECDSA');
	use_ok('Crypt::OpenSSL::Random');
}


my $keyfile = 'Kecc-gost.example.+012+46388.private';

END { unlink($keyfile) }


open( KSK, ">$keyfile" ) or die "$keyfile $!";
print KSK <<'END';
Private-key-format: v1.3
Algorithm: 12 (ECC-GOST)
PrivateKey: nBnGCP/hYTdJX0znDstyFTVYSA6b0nFeHy0FJUj7LhU=
Created: 20150102211707
Publish: 20150102211707
Activate: 20150102211707
GostAsn1: MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIgQg/9MiXtXKg9FDXDN/R9CmVhJDyuzRAIgh4tPwCu4NHIs=
END
close(KSK);


my $ksk = new Net::DNS::RR <<'END';
ecc-gost.example.	3600	IN	DNSKEY	257 3 12 (
	6VwgNT1BXxXNVpTQXcJQ82PcsCYmI60oN88Plbl028ruvl6DqJby/uBGULHT5FXmZiXBJozE6kP0
	+BirN9YPBQ== ) ; Key ID = 46388
END

ok( $ksk, 'set up ECC-GOST public ksk' );

my $key = new Net::DNS::RR <<'END';
ecc-gost.example.	3600	IN	DNSKEY	256 3 12 (
	LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScOgEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroFSRGR
	7ZYcx+YIQw== ) ; Key ID = 40691
END

ok( $key, 'set up ECC-GOST public key' );


my @rrset = ( $key, $ksk );
my $rrsig = create Net::DNS::RR::RRSIG( \@rrset, $keyfile );
ok( $rrsig, 'create RRSIG over rrset using private ksk' );

my $verify = $rrsig->verify( \@rrset, $ksk );
ok( $verify, 'verify RRSIG using ksk' ) || diag $rrsig->vrfyerrstr;

ok( !$rrsig->verify( \@rrset, $key ), 'verify fails using wrong key' );

my @badrrset = ($key);
ok( !$rrsig->verify( \@badrrset, $ksk ), 'verify fails using wrong rrset' );


exit;

__END__

