# $Id: 72-RRSIG-ECC-GOST.t 1287 2014-12-19 08:18:17Z willem $	-*-perl-*-
#
#	Simple known-answer test based on examples presented in RFC5933
#

use strict;


BEGIN {
	use Test::More;

	plan skip_all => 'optional Digest::GOST not installed'
			unless eval { require Digest::GOST; };

	plan skip_all => 'optional Digest::GOST::CryptoPro not installed'
			unless eval { require Digest::GOST::CryptoPro; };

	plan skip_all => 'optional Crypt::OpenSSL::EC not installed'
			unless eval { require Crypt::OpenSSL::EC; };

	plan skip_all => 'optional Crypt::OpenSSL::ECDSA not installed'
			unless eval { require Crypt::OpenSSL::ECDSA; };

	plan tests => 9;

	use_ok('Net::DNS::SEC');

	use_ok('Digest::GOST::CryptoPro');
	use_ok('Crypt::OpenSSL::EC');
	use_ok('Crypt::OpenSSL::ECDSA');
}


#my $keyfile = 'Kexample.net.+012+59732.private';
#
#END {
#	unlink($keyfile);
#}
#
#open( KSK, ">$keyfile" ) or die "$keyfile $!";
#print KSK <<'END';
#Private-key-format: v1.2
#Algorithm: 12 (ECC-GOST)
#GostAsn1: MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIgQg/9MiXtXKg9FDXDN/R9CmVhJDyuzRAIgh4tPwCu4NHIs=
#END
#close(KSK);


my $ksk = new Net::DNS::RR <<'END';
example.net. 86400   DNSKEY  257 3 12 (
				LMgXRHzSbIJGn6i16K+sDjaDf/k1o9DbxScO
				gEYqYS/rlh2Mf+BRAY3QHPbwoPh2fkDKBroF
				SRGR7ZYcx+YIQw==
				) ; key id = 40692
END

#ok( $ksk, 'set up ECC-GOST public ksk' );


my $key = new Net::DNS::RR <<'END';
example.net. 86400 IN DNSKEY 256 3 12 (
				aRS/DcPWGQj2wVJydT8EcAVoC0kXn5pDVm2I
				MvDDPXeD32dsSKcmq8KNVzigjL4OXZTV+t/6
				w4X1gpNrZiC01g==
				) ; key id = 59732
END

ok( $key, 'set up ECC-GOST public key' );


my $rr = new Net::DNS::RR <<'END';
www.example.net. 3600 IN A 192.0.2.1
END

my @rrset = ($rr);

my $rrsig = new Net::DNS::RR <<'END';
www.example.net. 3600 IN RRSIG A 12 3 3600 20300101000000 (
				20000101000000 59732 example.net.
				7vzzz6iLOmvtjs5FjVjSHT8XnRKFY15ki6Kp
				kNPkUnS8iIns0Kv4APT+D9ibmHhGri6Sfbyy
				zi67+wBbbW/jrA== )
END
ok( $rrsig, 'set up RRSIG over rrset' );


my $verify = $rrsig->verify( \@rrset, $key );
ok( $verify, 'verify RRSIG using key' ) || diag $rrsig->vrfyerrstr;

ok( !$rrsig->verify( \@rrset, $ksk ), 'verify fails using wrong key' );

my @badrrset = ($key);
ok( !$rrsig->verify( \@badrrset, $key ), 'verify fails using wrong rrset' );


exit;

__END__

