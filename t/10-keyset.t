#!/usr/bin/perl  -sw 
# Test script for keysetfunctionalty
# $Id: 10-keyset.t 270 2005-04-18 10:18:49Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 



#use Test::More  qw(no_plan);
use Test::More tests => 21;
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

my $rsakeyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 1 
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

my $dsakeyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 3 
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


my $sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));

my $sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa, 
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

if ($Net::DNS::RR::DS::_Babble){
    is ($ds[0]->string, "test.tld.	0	IN	DS	42495  1  1  ".
	"0ffbeba0831b10b8b83440dab81a2148576da9f6 ; xefoz-rupop-babuc-rugor-mavef-gybot-puvoc-pumig-mahek-tepaz-kixox",
	"DS 1 generated from keyset");                             # test 8-with babble


    is ($ds[1]->string, "test.tld.	0	IN	DS	9734  3  1  ".
	"0e045bfe67dec6e54d0f1338877a53841902ab4a ; xefib-gakiz-vynat-vacov-hyfeb-zugif-mecil-pegam-gykib-dapyg-pexox",
	"DS 1 generated from keyset");                             # test 9-with babble
}else{

    is ($ds[0]->string, "test.tld.	0	IN	DS	42495  1  1  ".
	"0ffbeba0831b10b8b83440dab81a2148576da9f6",
	"DS 1 generated from keyset");                             # test 8-without babble


    is ($ds[1]->string, "test.tld.	0	IN	DS	9734  3  1  ".
	"0e045bfe67dec6e54d0f1338877a53841902ab4a",
	"DS 1 generated from keyset");                             # test 9-without babble
}

    
##
#  Corupted keyset

$keysetpath="keyset-test-corrupt.tld.";
open (KEYSET,">$keysetpath") or die "Could not open $keysetpath";

print KEYSET $rsakeyrr->string ."\n";
print KEYSET $dsakeyrr->string ."\n";
my $sigstr=$sigrsa->string;

$sigstr =~  tr/A-Z/a-z/ ;  #Corrupt the signature's base64
$sigstr=~s/in	rrsig	dnskey/IN RRSIG DNSKEY/;  # fix what should not have been transponded

print KEYSET $sigstr ."\n";
print KEYSET $sigdsa->string . "\n";

close(KEYSET);

$keyset=Net::DNS::Keyset->new($keysetpath);



ok ( ! $keyset , "Corrupted keyset not loaded");   # test 10
is( $Net::DNS::Keyset::keyset_err , "RSA Verification failed on key test.tld 42495 "
     , "Correct Error message" );                   # test 11



#
# The packet contains a keyset as returned from a bind nameserver
# the keyset is signed with a signature valid untill 2030 06 .. 
#  After that the test may fail :-)

# This is the code sniplet used to get such a little packet as below.
#use Net::DNS::Resolver;
#my $res=Net::DNS::Resolver->new();
#$res->nameserver("10.0.53.204");
#$res->dnssec(1);
#my $a_packet=$res->send("sub.tld","DNSKEY");
#$a_packet->print;
#print unpack("H*",$a_packet->data);


my $UUencodedPacket="e6cc81a000010004000000010373756203746c
 640000300001c00c00300001000000200086010103050103bc54beaee1
 1dc1a29ba945bf69d0db27b364b2dfe60396efff4c6fb359127ea696e1
 4c66e1c6d23cd6f6c335e1679c61dd3fa4d68a689b8709ea686e43f175
 6831193903613f6a5f3ff039b21eed9faad4edcb43191c76490ca0947a
 9fa726740bc4449d6c58472a605913337d2dbddc94a7271d25c358fdaa
 60fe1272a5f8b9c00c00300001000000200086010003050103f6d63a8a
 b9f775a0c7194d67edb5f249bf398c3d27d2985facf6fb7e25cc35c876
 2eb8ea22200c847963442fb6634916dc2ec21cdbf2c7378799b8e7e399
 e751ca1e25133349cab52ebf3fe8a5bc0239c28d64f4d8f609c191a7d2
 d364578a159701ef73af93946b281f0aac42b42be17362c68d7a54bbb8
 fa7bc6f70f455a75c00c002e000100000020009b003005020000006470
 dc814040c02ced39d40373756203746c6400a7d9db75a4115794f871ec
 71fc7469c74a6be1cf95434a00363506b354bf15656f7556c51355c8dc
 ac7f6c0a4061c0923e0bf341094e586619c2cb316949772ce5bd1e9949
 f91b016f7e6bee0f6878e16b6e59ece086f8d5df68f048524e1bff3c09
 dd15c203d28416600e936451d1646e71611ec95e12d709839369cbc442
 c0c00c002e000100000020009b003005020000006470dc814040c02ced
 fbaf0373756203746c640017c6e59f317119da812c6b1e175e8aaec742
 35a4bfad777e7759fa2daf7959f9611c26e11adde9bdc901c624ca6965
 7b79653495e22647c5e0e5bedfe5524397d769d816746d10b2067472b4
 f9b04fbde8e39d7861bd6773c80f632f55b46c7a537a83f0b5a50200c9
 d2847b71d9dfaa643f558383e6e13d4e75f70029849444000029100000
 0080000000";


$UUencodedPacket =~ s/\n//g; 
$UUencodedPacket =~ s/\s//g; 

my $packetdata=pack("H*",$UUencodedPacket);
my $packet = Net::DNS::Packet->new(\$packetdata);


$keyset=Net::DNS::Keyset->new($packet);
is (ref($keyset), "Net::DNS::Keyset", "Keyeset object from packet");  # test 12

is (join(" ",sort($keyset->verify)),"14804 64431","Verify method returned the two proper keytags");     # test 13




my $keyset2= Net::DNS::Keyset->new($datarrset,"./");
is (ref($keyset2), "Net::DNS::Keyset", "Keyeset object from DNSKEY RR and signature");  

# test 14
#print $Net::DNS::Keyset::keyset_err;
#$keyset->print;

unlink($keysetpath);




#########
###

my $rr; 
my @keyrr;
my @keyrr2;
my @sigrr;



# Note that the order on pushing the RRsigs is important for
# succesfully testing.

# All signatures have expiration date in 2030... this test should work for a while

$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQOxFlzX8vShSG3JG2J/fngkgy64RoWr8ovG
					e7MuvPJqOMHTLM5V8+TJIahSoyUd990ictNv
					hDegUqLtZ8k5oQq44viFCU/H1apdEaJnLnXs
					cVo+08ATlEb90MYznK9K0pm2ixbyspzRrrXp
					nPi9vo9iU2xqWqw/Efha4vfi6QVs4w==
					) ");

push(@keyrr,$rr);
push(@keyrr2,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO4jhl6ilWV2mYjwWl7kcxrYyQsnnbV7pxX
					m48p+SgAr+R5SKyihkjg86IjZBQHFJKZ8RsZ
					dhclH2dikM+53uUEhrqVGhsqF8FsNi4nE9aM
					ISiX9Zs61pTYGYboYDvgpD1WwFbD4YVVlfk7
					rCDP/zOE7H/AhkOenK2w7oiO0Jehcw==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);
my $poppedkey=Net::DNS::RR->new($rr->string);


$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO5fWabr7bNxDXT8YrIeclI9nvYYdKni3ef
					gJfU749O3QVX9MON6WK0ed00odQF4cLeN3vP
					SdhasLDI3Z3TzyAPBQS926oodxe78K9zwtPT
					1kzJxvunOdJr6+6a7/+B6rF/cwfWTW50I0+q
					FykldldB44a1uS34u3HgZRQXDmAesw==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO6uGWsox2oH36zusGA0+w3uxkZMdByanSC
					jiaRHtkOA+gIxT8jmFvohxQBpVfYD+xG2pt+
					qUWauWPFPjsIUBoFqHNpqr2/B4CTiZm/rSay
					HDghZBIMceMa6t4NpaOep79QmiE6oGq6yWRB
					swBkPZx9uZE7BqG+WLKEp136iwWyyQ==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);

$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 11354 example.com.
					GTqyJTRbKJ0LuWbAnNni1M4JZ1pn+nXY1Zuz
					Z0Kvt6OMTYCAFMFt0Wv9bncYkUuUSMGM7yGG
					9Z7g7tcdb4TKCqQPYo4gr3Qj/xgC4LESoQs0
					yAsJtLUiDfO6e4aWHmanpMGyGixYzHriS1pt
					SRzirL1fTgV+kdNs5zBatUHRnQc=) ");

push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 28109 example.com.
					WemQqA+uaeKqCy6sEVBU3LDORG3f+Zmix6qK
					9j1WL83UMWdd6sxNh0QJ0YL54lh9NBx+Viz7
					gajO+IM4MmayxKY4QVjp+6mHeE5zBVHMpTTu
					r5T0reNtTsa8sHr15fsI49yn5KOvuq+DKG1C
					gI6siM5RdFpDsS3Rmf8fiK1PyTs= )");
push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 33695 example.com.
					M3yVwTOMw+jAKYY5c6oS4DH7OjOdfMOevpIe
					zdKqWXkehoDg9YOwz8ai17AmfgkjZnsoNu0W
					NMIcaVubR3n02bkVhJb7dEd8bhbegF8T1xkL
					7rf9EQrPmM5GhHmVC90BGrcEhe//94hdXSVU
					CRBi6KPFWSZDldd1go133bk/b/o= )");
push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 39800 example.com.
					Mmhn2Ql6ExmyHvZFWgt+CBRw5No8yM0rdH1b
					eU4is5gRbd3I0j5z6PdtpYjAkWiZNdYsRT0o
					P7TQIsADfB0FLIFojoREg8kp+OmbpRTsLTgO
					QYC95u5WodYGz03O0EbnQ7k4gkje6385G40D
					JVl0xVfujHBMbB+keiSphD3mG4I= )");


push(@sigrr,$rr);
my @errors;


my $ks=Net::DNS::Keyset->new(\@keyrr,\@sigrr);

ok($ks,"Keyset created from two arrays.");
my @result;
@result=$ks->keys;
ok(eq_array(\@result,\@keyrr),"Keys out equal to keys in");   # test 16
@result=$ks->sigs;
ok(eq_array(\@result,\@sigrr),"Sigs out equal to sigss in");  # test 17





open (KEYSET,">$keysetpath") or die "Could not open $keysetpath";

$datarrset= [ $rsakeyrr, $dsakeyrr ];


$sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));

$sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature created');                               # test 18

print KEYSET $rsakeyrr->string ."\n";
print KEYSET $dsakeyrr->string ."\n";
print KEYSET $sigrsa->string . "\n";
close(KEYSET);


$keyset=Net::DNS::Keyset->new($keysetpath);

is (join(" ",sort($keyset->verify)),"42495","Verify method returned the  keytags");     # test 13

ok (! $keyset->verify(9734),"Verification agains keytag 9734 failed"); # Test 19


is( $Net::DNS::Keyset::keyset_err , "No signature made with 9734 found"
     , "Correct Error message" );                   # test 20



unlink($keysetpath);
unlink($keypathdsa);
unlink($keypathrsa);



0;








