# $Id: 61-SIG0-RSAMD5.t 1291 2015-01-06 07:44:34Z willem $	-*-perl-*-
#

use strict;


BEGIN {
	use Test::More tests => 9;

	use_ok('Net::DNS::SEC');

	use_ok('Crypt::OpenSSL::RSA');
}


my $keyfile = 'Krsamd5.example.+001+19713.private';

END { unlink($keyfile) }


open( KEY, ">$keyfile" ) or die "$keyfile $!";
print KEY <<'END';
Private-key-format: v1.2
Algorithm: 1 (RSA)
Modulus: vtxbVKsOv7NMaRyMnHSurDsd3NMU5QjQwPMwPfBhXjoBL2WFW8mGWc3SAMhRZG0fmUPQ3yjTULViWuJgCe0N2vFyUhM8oxWQSVAJ5FRHMQQ73UAyNIEUW/hVSD3e3qiWrtYO2FQbtL/a60Ey0upk2qHlPZnxzRoQ6bfiCh9yPzG+5Rd2lIA9LaCSsupiEte/e95Zai9qbizlMXeeIXGv9Brq+DkWTx7VgGKcrlve2ZXisc/27v1NiJUU33X76K/VU2ecDnVDJx9WI+CffYKQSuRN8HRbyU30UEl6k6k3W6/qnD7f04VY3/oqvtai/VUnTqowS4djHiUW9xE3b00BoQ==
PublicExponent: AQAB
PrivateExponent: POI6WDYBDHH7zAQJbtdh6RsqmYjUP4OiZAqvtvJ5fP9v5VizQ+Zzby5S8WD1Zd3RmKijdqylTDewWmGgVUpDgzZGS5xLWZLFZj2cCjRASYiaOCgEW+9ZOUVsnxDtiYWqG7e5IJUkCXKyOR2hQtr2tS+z2wTCt7S69HNuLeB+J13/F0MfdCYXeBuSZs28afp5chwDeLjBxT4tZR9NTNtKDRLVZZdseQsJOkf8PK5PYKx190oZMmHMfJBtjCbOHDaocv15RUhchVycOa0xS+FW1exP2rUm6shPuyXGvuxJxqDLNLxIE8b3+OuHn6y2RuwYh5jacVhQN+JzWG1EG3R+4Q==
Prime1: +D2LUs99ig9K9wIo/BZ84VUuGmtYjMLdwJxespH6qjXYp6z7T5cPEUEDlOGNHZJFBg5f+FtwuhT9jggFTvIcWx4Vs/GMS4IzAM3XAuPEMBi6Q19y+20PTCmQBBn22ae5pus1KCJCsNra89IjHuw7jol6nDBEcV8u9kwqTMfjxkU=
Prime2: xNOm/0NWqHZwUjbQsKk5GjHjJIMcMVQ4pxns+ph+pwJbNod0Hrt/DGe3gjIeUvxHWgiCYYMtXtdhOtDSyBxbCwA5rqxbGInY5JP09EnGLfNIaY2KNbkZFP53zguMyfbvzQpcgp7hL9iaqjYk9PLGraobWU1cJoVNa+RTLtOuwa0=
Exponent1: HE1oBRkDByqXMXJdmeA2fLppdzml7uaIwd0SLunV2nIpMXTXckuWvDDdZ6wPmr+Cfx5Ectx6Db0262qesFGKShk0AEAZ7sH5bq4JRZsSUyl+kw/e3CujAtv6P312V3p4AD/w35KIaAGL1SCwQGZOpAGoqQYXx5VClXI5oGdp4ME=
Exponent2: oNXXA4XSHUzTEctrEsDlQWt8kcx1UDXjKWD9DfVooS5CvLdJAwfxlIB4KvKrZuJxp7eGWwpnG7Xh5L7ZTt4k40Nm3z5GHjIeQwJISwqx38CJ7n7Tbnz3avlZisxTWoHniGQsHiyYFJHqKKaf4m00PprfSET3xR5umnh0JLKjfe0=
Coefficient: W62yxJ2Quz0qKU/EWoASh4G1YIeCblesSuZrQAHqMIwwhasRV/TYhicgj9zIoKI/QQj5di9AI+v+1R/YMXPTGMWIfSBvx8BrS1WfJnbWazv9xCHQzYpzHivVfsvyoWCwZ46W2h9KtXhYQbhBNKCtspJ9YinoQ0SQbYUIQg/yAcg=
END
close(KEY);


my $key = new Net::DNS::RR <<'END';
RSAMD5.example.	3600	IN	KEY	256 3 1 (
	AwEAAb7cW1SrDr+zTGkcjJx0rqw7HdzTFOUI0MDzMD3wYV46AS9lhVvJhlnN0gDIUWRtH5lD0N8o
	01C1YlriYAntDdrxclITPKMVkElQCeRURzEEO91AMjSBFFv4VUg93t6olq7WDthUG7S/2utBMtLq
	ZNqh5T2Z8c0aEOm34gofcj8xvuUXdpSAPS2gkrLqYhLXv3veWWovam4s5TF3niFxr/Qa6vg5Fk8e
	1YBinK5b3tmV4rHP9u79TYiVFN91++iv1VNnnA51QycfViPgn32CkErkTfB0W8lN9FBJepOpN1uv
	6pw+39OFWN/6Kr7Wov1VJ06qMEuHYx4lFvcRN29NAaE= ) ; Key ID = 19713
END

ok( $key, 'set up RSA public key' );

my $update = new Net::DNS::Update('example.com');
ok( $update, 'set up new update packet' );

$update->push( update => rr_add('foo.example.com A 10.1.2.3') );
ok( scalar $update->authority(), 'insert record in update packet' );

$update->sign_sig0($keyfile);
ok( scalar $update->additional(), 'sign update packet (SIG0)' );


my $buffer = $update->data;		## SIG0 generation occurs here
my $packet = new Net::DNS::Packet( \$buffer );


my ($sig) = reverse $packet->additional;
my $verify = $sig->verify( $packet, $key );
ok( $verify, 'verify packet using public key' ) || diag $packet->vrfyerrstr;

my $bad = new Net::DNS::RR <<'END';
RSAMD5.example.	3600	IN	KEY	256 3 1 (
	AwEAAdDembFMoX8rZTqTjHT8PbCZHbTJpDgtuL0uXpJqPZ6ZKnGdQsXVn4BSs8VJlH7+NEv+7Spq
	Ncxjx6o86HhrvFg5DsDMhEi5MIqlt1OcUYa0zUhFSkb+yzOSnPL7doSoaW8pxoX4uDemkfyOY9xN
	tNCNBJcvmp1Uvdnttf7LUorD ) ; Key ID = 21130
END
ok( !$sig->verify( $packet, $bad ), 'verify fails using wrong key' );

$packet->push( update => $bad );
ok( !$sig->verify( $packet, $key ), 'verify fails for modified packet' );


exit;

__END__

