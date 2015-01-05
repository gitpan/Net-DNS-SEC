# $Id: 73-RRSIG-ECDSAP256SHA256.t 1289 2015-01-05 10:08:59Z willem $	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More;

	plan skip_all => 'optional Crypt::OpenSSL::EC not installed'
			unless eval { require Crypt::OpenSSL::EC; };

	plan skip_all => 'optional Crypt::OpenSSL::ECDSA not installed'
			unless eval { require Crypt::OpenSSL::ECDSA; };

	plan tests => 9;

	use_ok('Net::DNS::SEC');

	use_ok('Crypt::OpenSSL::EC');
	use_ok('Crypt::OpenSSL::ECDSA');
}


my $keyfile = 'Kecdsap256sha256.example.+013+26512.private';

END { unlink($keyfile) }


open( KSK, ">$keyfile" ) or die "$keyfile $!";
print KSK <<'END';
Private-key-format: v1.2
Algorithm: 13 (ECDSAP256SHA256)
PrivateKey: h/mc+iq9VDUbNAjQgi8S8JzlEX29IALchwJmNM3QYKk=
END
close(KSK);


my $ksk = new Net::DNS::RR <<'END';
ECDSAP256SHA256.example.	3600	IN	DNSKEY	257 3 13 (
	z72glzDFUwYbpcruyKn+qYSbBGDymZJBt0wSFpY05RfuG32tqSqesr98/mt8i7fa4faC8UvmL2zj
	kOsTo3t2og== ) ; Key ID = 26512
END

ok( $ksk, 'set up ECDSA public ksk' );


my $key = new Net::DNS::RR <<'END';
ECDSAP256SHA256.example.	3600	IN	DNSKEY	256 3 13 (
	ZVcqO8GnPFjjqXLRN8CiH1Cwx2n9s9Eg1NVXZunT5kkfwd7b7GlaliMcCPw+tZkTZNMdm8ge5Q71
	8UIKvGZMNw== ) ; Key ID = 24312
	)
END

ok( $key, 'set up ECDSA public key' );


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

