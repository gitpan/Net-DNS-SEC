#!/usr/bin/perl  -sw 
# Test script for keysetfunctionalty
# $Id: 10-keyset.t,v 1.6 2003/08/27 14:09:25 olaf Exp $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 



#use Test::More  qw(no_plan);
use Test::More tests => 12;
use strict;


BEGIN {use_ok('Net::DNS'); }                                 # test 1
BEGIN {use_ok('Net::DNS::Keyset'); }                                 # test 1


#
# RSA keypair 
#
my $keypathrsa="Ktest.tld.+001+42495.private";
my $privrsakey= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 1 (RSA)
Modulus: ovtC5gQH1fuAnQqMvNctGfX3o2F82164fO7toGiWddiLTuWxrXoHwcpIFLO+hJR9Xxr1gaWh6od66CJnOzBpIQjIe/htpRO2nmLFF5+cB3QRRMGQWmq3bPCXDBHE/Jx8ihzWZavXwIUN+oLqhnWbkT6sYGH8M+9VSW9rfeil/+c=
PublicExponent: Aw==
PrivateExponent: bKeB7q1ajqerE1xd0zoeEU6lF5ZTPOnQU0nzwEW5o+WyNJkhHlFagTGFYyJ/Aw2o6hH5ARkWnFpR8BbvfMrwv6AeCrahtJgilCpCYxwusOOikbkGR/sXP5ObscRmEuhfzVYBV62yMc34MyspHzXHNZAL+SgRswopy6MgWdAII2s=
Prime1: 0GNRLAYLvgaIZ+8o/fVST6WEhQd4bDIEHnBtIxHj9NIrHL/nIerA80sth+Pwfed2zp109U+zvcizUSfJDbHRsQ==
Prime2: yDgaunUKcXw3u3JZ92Crzvflpv92BeKJdL0USBn8Sxqq/xR7BWG03M6AOkjnJwlKF/z1sJHzok3kqZMuIuf5Fw==
Exponent1: iuzgyAQH1ARa7/TF/qOMNRkDA1pQSCFYFErzbLaX+IwcvdVEwUcrTNzJBUKgU++kib5N+N/NKTB3i2/bXnaLyw==
Exponent2: hXq8fE4G9lLP0kw7+kByifqZGf+kA+xboyi4MBFS3Lxx/2L8rkEjPd8AJttExLDcD/35IGFNFt6YcQzJbJqmDw==
Coefficient: gAeUUI6YOtdNAh3kS7pOzYfn0ZrUCV8bGpZoaXANk2RL2zUiaSSa4wudhpHwMJt+psNkkiQyf4v600uHbxro4Q==
ENDRSA

my $rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok( $rsakeyrr, 'RSA public key created');     # test 5



my $keypathdsa="Ktest.tld.+003+09734.private";
my $privdsakey= << 'ENDDSA' ;
Private-key-format: v1.2
Algorithm: 3 (DSA)
Prime(p): 7m5wm/8KMO1fLaBB2Wbq3s0/jMudrauMDg1G3SrOWOgX2AITudhGzT0c0FTxztM81IbmVETd/l5XXUEG0/joY2DNeyxD6I4Y94VcgUyf0l9ronUw+wXBhWCuueJPXSDIbbUDdcI7srlslykC+LQRnsbxB5YJMgmkPaPZU8GpRcc=
Subprime(q): jRgd5fwOUwUmNpcD6Uzs/tMzy3U=
Base(g): a0/+JhZhnci+P8/GOvnokG3NAF10o0Pf6/oz5UpcmX89KqjPvn9aRTRI9sM2AJgFBkzrQhXcx9NPvhneW0zN/baQhaUkupJ8YazNkkVKfOM6aH9h8ONVgGNRiLEBILQa07EMzce9/+JDYFbOCajJqhb9MZlTau17GDDK+r4okJ0=
Private_value(x): C7O98kp8pfDdqeuvD83nf1xc4sI=
Public_value(y): kFKU1HfmfRxPWwS9mA3FBHZ9LbmEizsH7vFSD7m31crIDVpxIO02bhKyFAuurKNh6naG4iTo3ak0yv6/bP8VNFIxN2QHPnnQL72ctUpvMLe+kWX7fGXuXWPIUCWVnbAeP2SnxpjxU039E9A2Rk6Dp9Eu0oXsM8hcUUnRv6ekycA=
ENDDSA

open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
print RSA $privrsakey;
close(RSA);

my $dsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 3 
CI0YHeX8DlMFJjaXA+lM7P7TM8t17m5wm/8KMO1fLaBB2Wbq3s0/jMud 
rauMDg1G3SrOWOgX2AITudhGzT0c0FTxztM81IbmVETd/l5XXUEG0/jo 
Y2DNeyxD6I4Y94VcgUyf0l9ronUw+wXBhWCuueJPXSDIbbUDdcI7srls 
lykC+LQRnsbxB5YJMgmkPaPZU8GpRcdrT/4mFmGdyL4/z8Y6+eiQbc0A 
XXSjQ9/r+jPlSlyZfz0qqM++f1pFNEj2wzYAmAUGTOtCFdzH00++Gd5b 
TM39tpCFpSS6knxhrM2SRUp84zpof2Hw41WAY1GIsQEgtBrTsQzNx73/ 
4kNgVs4JqMmqFv0xmVNq7XsYMMr6viiQnZBSlNR35n0cT1sEvZgNxQR2 
fS25hIs7B+7xUg+5t9XKyA1acSDtNm4SshQLrqyjYep2huIk6N2pNMr+ 
v2z/FTRSMTdkBz550C+9nLVKbzC3vpFl+3xl7l1jyFAllZ2wHj9kp8aY 
8VNN/RPQNkZOg6fRLtKF7DPIXFFJ0b+npMnA");

ok( $dsakeyrr, 'RSA public key created');      # test 6



open (DSA,">$keypathdsa") or die "Could not open $keypathdsa";
print DSA $privdsakey;
close(DSA);

# Create keysets

my $keysetpath="t/keyset-test.tld.";

open (KEYSET,">$keysetpath") or die "Could not open $keysetpath";

my $datarrset= [ $rsakeyrr, $dsakeyrr ];


my $sigrsa= create Net::DNS::RR::SIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));

my $sigdsa= create Net::DNS::RR::SIG($datarrset,$keypathdsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature created');                               # test 7

print KEYSET $rsakeyrr->string ."\n";
print KEYSET $dsakeyrr->string ."\n";
print KEYSET $sigrsa->string . "\n";
print KEYSET $sigdsa->string . "\n";
close(KEYSET);

my $keyset;
$keyset=Net::DNS::Keyset->new($keysetpath);
use Data::Dumper;
is (ref($keyset), "Net::DNS::Keyset", "Keyeset object read");

$keyset=Net::DNS::Keyset->new($datarrset);
is (ref($keyset), "Net::DNS::Keyset", "Keyeset object created");

my @ds=$keyset->extract_ds;

is ($ds[0]->string, "test.tld.	0	IN	DS	42495  1  1  ".
    "0ffbeba0831b10b8b83440dab81a2148576da9f6 ; xefoz-rupop-babuc-rugor-mavef-gybot-puvoc-pumig-mahek-tepaz-kixox",
    "DS 1 generated from keyset");                             # test 8


is ($ds[1]->string, "test.tld.	0	IN	DS	9734  3  1  ".
    "0e045bfe67dec6e54d0f1338877a53841902ab4a ; xefib-gakiz-vynat-vacov-hyfeb-zugif-mecil-pegam-gykib-dapyg-pexox",
    "DS 1 generated from keyset");                             # test 9
    
##
#  Corupted keyset

$keysetpath="keyset-test-corrupt.tld.";
open (KEYSET,">$keysetpath") or die "Could not open $keysetpath";

print KEYSET $rsakeyrr->string ."\n";
print KEYSET $dsakeyrr->string ."\n";
my $sigstr=$sigrsa->string;
$sigstr =~  s/a/0/g ;
print KEYSET $sigstr ."\n";
print KEYSET $sigdsa->string . "\n";
close(KEYSET);

$keyset=Net::DNS::Keyset->new($keysetpath);



ok ( ! $keyset &&
     $Net::DNS::Keyset::keyset_err eq "RSA Verification failed on key test.tld 42495"
     , "Corrupted keyset is not loaded" );                   # test 10



#
# The packet contains a keyset as returned from a bind nameserver
# the keyset is signed with a signature valid untill 2030 06 .. 
#  After that the test may fail :-)

my $UUencodedPacket="4584850000010004000300040373756203746c640000190001c00c
001900010000006401990100030308b19cf517bd237a60ed002ac4f79b4e96e891b61be6765
a1474a1446e35f1499d8661c517f7137c48919197d1503299681b5723aa34b6c9114e37696a
b32e0801254f1ac6a90999f3de274cb538728d1463f751d26589b71b0717a2b755c198594e9
1248da18e25416142996f1aad56252b18ea8d980bdf123f280df6de006dd6d82d39f9d9e364
7f9486c12561321a6ef8e7472d9f607bd3fc4d488f4fce0debfd68cb29c4d271f49b403d35b
78965e8806dc38ccea8a84142ad16029c0b9d03abe9b669f2a39ad0752400ad38f178694f39
8947da1f0d0523aab70c72e067071d4bdae27e1729c64e68ef536cd26b1d02aa9d0901824aa
1083ccf01ca61ecaa636ba85fa90cf849103be30e6bffcb15abb4a9d34f7d290c223f64c7f2
79ce87fa5eaad7934db6d0f120b245ea48ca985f3af9332f3ca416999bbbedc9a6b27f7c534
1e46f5139fd2f43b8c356d8da8f39b673fdcb84e57d6ebe25b71a92a6f8787f1e5cdd25a627
41b3486a7a99323fbeaed0571043552ee47eedcd0f010307bd4bb3b8807423b3f615552f6e2
26328006d2bb7c00c00190001000000640086010003010103f0d366fd32747c689a653b2235
081d2ed730468bdc4500f899d4d91d0e5aa77b79525e9187cd035385fd7a108764f9d882ae8
48e15dcf78c0ff47e71db1bcd30437e64d98bd556aa281c77a5f6701e3072454a0033815d87
b7b84e9da81a2b4578cdb72f0e71e6ea4ca23ee2c4c6f9277a12e0e86f5bfb236d649d20835
bc719c00c0018000100000064009b001901020000006471c5bd613d5a3d9f5bc70373756203
746c640008e835977d0429c6c29f23eda36c7db02460bcb091908b787c55dae3c5ed803dbcc
c87c7ea73899b98536680de82adf5ce75578c757df3880435c3df60a101d8bc84b2e9bbab11
02e6ea79948d8f5c1f104878e5d649a83cb9048eefa393bf3900b560482aa703b73a80708d3
036a74a905676174707de71a0a825b0385d00c2c00c00180001000000640044001903020000
006471c5bd613d5a3d9f4d8e0373756203746c640008855400b2671b25d2731fddf11abf1bc
ca7cfac567a413712e94cf9f17a001a392cf388a124c9e0bfc00c0002000100000064000502
6e73c00cc00c0018000100000064009b000201020000006471c5bd613d5a3d9f5bc70373756
203746c640053e73d03e1c0f28dbeeffe0ff8e78147a07c119473998edf9aecc3c0dcba37ac
7415aa11c6b7cc19a8548aef432c546860055efd8b1697b0fa29ccfeaea69627a0a90ec7a79
39ee20809efdf0354a002e702448e8f0b2a7f73375be746d42590f3a5041b68e971c7aeba3b
6a89a9b1c16f11eb88d0e1525e9965878aff1a3a11c00c00180001000000640044000203020
000006471c5bd613d5a3d9f4d8e0373756203746c6400086e4aaf9e914715a992a5ae363e29
9a71aaaf1e688549882bc6ba7de9d811272bedcca4952e8cd6bac3530001000100000064000
40a0035cbc3530018000100000064009b000101030000006471c5bd613d5a3d9f5bc7037375
6203746c64009b4997f6577c13eb127d4523dea6df665c0943db14e899cb30c92b73e41786c
d85916d6e85526420e021bfb529a0ab037f2e9ecc9bbeb853d93de6897d03baa47116f6af23
6328b8b856cd29d1e7ec21755e4f193c283f792a158d1512dce6a4a797ea15a6b917cd8c759
b893a180ef6091917ebd9e0cfb52b347abb3076468dc3530018000100000064004400010303
0000006471c5bd613d5a3d9f4d8e0373756203746c64000877f90f542dd494d1514275f9cd6
34043ae6ada8c9aecd2e333537ec8d4c087e2a17a6f371c72f0d50000291000000080000000";

$UUencodedPacket =~ s/\n//g; 

my $packetdata=pack("H*",$UUencodedPacket);
my $packet = Net::DNS::Packet->new(\$packetdata);


$keyset=Net::DNS::Keyset->new($packet);
is (ref($keyset), "Net::DNS::Keyset", "Keyeset object from packet");  # test 11



my $keyset2= Net::DNS::Keyset->new($datarrset,"./");
is (ref($keyset2), "Net::DNS::Keyset", "Keyeset object from KEY RR and signature");  

# test 11
#print $Net::DNS::Keyset::keyset_err;
#$keyset->print;


unlink($keypathdsa);
unlink($keypathrsa);
unlink($keysetpath);




0;






