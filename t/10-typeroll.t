#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 10-typeroll.t,v 1.2 2004/01/27 10:45:49 olaf Exp $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/10-typeroll.t

use Net::DNS::RR::RRSIG;

use Test::More tests=>38;
use strict;

BEGIN {use_ok('Net::DNS'); }                                 # test 1



my $datarrset;
my ($datarr1, $datarr2, $datarr3);
my $datastring1="test.tld.		7000	IN	NS	ns.test.tld.";
my $datastring2="test.tld.		7000	IN	NS	ns.foo.tld.";
my $datastring3="test.tld.		7000	IN	NS	ns.boo.tld.";



$datarr1=  new Net::DNS::RR($datastring1);
ok ( $datarr1, 'data RR 1 loaded ');                         # test 2
$datarr2=  new Net::DNS::RR($datastring2);
ok ( $datarr2, 'data RR 2 loaded ');                         # test 3
$datarr3=  new Net::DNS::RR($datastring3);
ok ( $datarr3, 'data RR 3 loaded ');                         # test 4
$datarrset = [ $datarr1, $datarr2 , $datarr3  ] ;


##############################################
# In the following tests we first sign a DNSKEY and then verify it again.
# We do this for both RSA and DSA.
# This is a consistency check 
# 
# The private key will be written to disk first.
#
# Keypairs generated with dnssec-keygen. (9.2.0rc1)


#
# RSA keypair 
#
my $keypathrsa="Ktest.tld.+001+11567.private";
my $privrsakey= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 1 (RSA)
Modulus: 6ASwF3rSBFnBBQ7PmdWJnNkT2XkbZP5Be28SyTohsnuT1Rw7OlbNVNiT+4S04JUS0itVbvgtYmDZGMU3nfZP+er20uJRo/mu6hSkJW3MX5ES8o/GnOST1zSCH1+aA1Y6AlhfLebC+ysVKftLYnEco6oHNioYOmYHozYr5d0tL/s=
PublicExponent: Aw==
PrivateExponent: mq3KulHhWDvWA181ETkGaJC35lC87f7WUkoMhibBIae342gnfDneOJBip63N6w4MjBzjn1AeQZXmEIN6aU7f+q0Fwsyl4FzrSa8ehjfTS4u4YZE/Zk9rv0VIZuYwyccgLEBLYNBYRLbkbuSqDspw+Th8dCGy7XZ06eRkGZSNMjs=
Prime1: 9Fssra0OAl4kNX105Xdrnb7kS+/6QgWeJeBJCuajjWQ0uRiEClDzjVVVr6BW2DixP+6RCbSDioSIqsNc546UtQ==
Prime2: 8xMCAavFa+/XWHjnNJgCob976feJK2yaJrU7+2oxHiWLPtWYo+2gi2kt9Kv1aTp8lV327ddSqdO7tNJilsrP7w==
Exponent1: oudzHnNerD7CzlOjQ6TyaSnth/VRgVkUGUAwse8Xs5gjJhBYBuCiXjjjymrkkCXLf/RgsSMCXFhbHII977RjIw==
Exponent2: ogysAR0uR/U6OvtEzbqsa9T9RqUGHPMRbyN9UkbLaW5c1I5lwp5rB5tz+HKjm3xTDj6kno+McTfSeIxBudyKnw==
Coefficient: Cxwv14w+KY7rmiO4U0giXqOij9gON7TiByj5dQjHGUQdaQEJ0zK2SlxouEfgi3hcxTGI753pFmW0cF/MDjFURw==
ENDRSA

my $rsakeyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");


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
8VNN/RPQNkZOg6fRLtKF7DPIXFFJ0b+npMnA


");

ok( $dsakeyrr, 'RSA public key created');      # test 6



open (DSA,">$keypathdsa") or die "Could not open $keypathdsa";
print DSA $privdsakey;
close(DSA);

# Create the signature records.

my $sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature created');                               # test 7

my $sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));
ok ( $sigdsa, 'DSA signature created');                               # test 8



# Verify the just created signatures
ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA sig verifies');        # test 9
# Verify the just created signatures
ok ($sigdsa->verify($datarrset,$dsakeyrr), 'DSA sig verifies');       # test 10

# on the other hand checking against the wrong key should fail.
ok (! $sigrsa->verify($datarrset,$dsakeyrr), 
    'RSA sig fails agains corrupt data');                             # test 11

ok (! $sigdsa->verify($datarrset,$rsakeyrr),
    'DSA sig fails agains corrupt data');                             # test 12

# Now corrupt the key and test again.. that should fail
# Corruption is very hard to notice.. we modified one letter
# in the base 64 representation.

my $corrupt_rsakeyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfA 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok (!$sigrsa->verify($datarrset,$corrupt_rsakeyrr),'RSA fails agains corrupt key');
                                                                     # test 13

my $corrupt_dsakeyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 3 
CI0YHeX8DlMFJjaXA+lM7P7TM8t17m5wm/8KMO1fLaBB2Wbq3s0/jMue 
rauMDg1G3SrOWOgX2AITudhGzT0c0FTxztM81IbmVETd/l5XXUEG0/jo 
Y2DNeyxD6I4Y94VcgUyf0l9ronUw+wXBhWCuueJPXSDIbbUDdcI7srls 
lykC+LQRnsbxB5YJMgmkPaPZU8GpRcdrT/4mFmGdyL4/z8Y6+eiQbc0A 
XXSjQ9/r+jPlSlyZfz0qqM++f1pFNEj2wzYAmAUGTOtCFdzH00++Gd5b 
TM39tpCFpSS6knxhrM2SRUp84zpof2Hw41WAY1GIsQEgtBrTsQzNx73/ 
4kNgVs4JqMmqFv0xmVNq7XsYMMr6viiQnZBSlNR35n0cT1sEvZgNxQR2 
fS25hIs7B+7xUg+5t9XKyA1acSDtNm4SshQLrqyjYep2huIk6N2pNMr+ 
v2z/FTRSMTdkBz550C+9nLVKbzC3vpFl+3xl7l1jyFAllZ2wHj9kp8aY 
8VNN/RPQNkZOg6fRLtKF7DPIXFFJ0b+npMnA");


ok (! $sigdsa->verify($datarrset,$corrupt_dsakeyrr),'DSA fails agains corrupt key');
                                                                     # test 14


# Now test some DSA stuff

my $dsrr=create Net::DNS::RR::DS($rsakeyrr);
ok( $dsrr,'DS created from DNSKEY RR');                                # test 15


ok( $dsrr->verify($rsakeyrr),'DS matches DNSKEY');                        # test 16



my $dsrr2=Net::DNS::RR->new("test.tld.	0	IN	DS	42495  1  1  0ffbeba0831b10b8b83440dab81a2148576da9f6");


ok( $dsrr,'DS(2) created from string');                              # test 17


ok( $dsrr->verify($rsakeyrr),'DS(2) matches DNSKEY');                      # test 18



my ($nlkey1, $nlsig1, $nlNS1, $nlNS2, $nlNS3, $nldatarrset);

    $nlNS1=new Net::DNS::RR(" host100.ws.disi.  600   IN A    10.1.1.100");
    $nlNS2=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.2.100");
    $nlNS3=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.3.100");
    $nldatarrset=[$nlNS1,$nlNS3, $nlNS2];

my $dsasigrr=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathdsa
				    );
ok( $dsasigrr, 'DSA signature with bind generated key');             # test 19


my $rsasigrr=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathrsa
				    );
ok( $rsasigrr, 'RSA signature with bind generated key');            # test 20


ok( $dsasigrr->verify($nldatarrset,$dsakeyrr),'DSA sig (test 2) verifies');       # test 21

is( $dsasigrr->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    # test 22

ok( $rsasigrr->verify($nldatarrset,$rsakeyrr),'RSA sig (test 2) verifies');       

is( $rsasigrr->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    # test 24



#
# SOA with escaped dot.
$datarr1 = Net::DNS::RR->new("test.tld.	7000	IN	SOA (
			     ns.test.tld.
			     first\.last.test.tld. 
			     2002042603 43200 7200 1209600 7200)");

$datarrset = [ $datarr1 ] ;
$sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature over SOA with escaped dot  created');                #test 25


ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA sig over SOA  with escaped dot verifies');        #test 26



# clean the private key files (not needed no more)



# Cross check with a  signature generated with bind tools.
#test fails after October 2030 :

my $bindkey=Net::DNS::RR->new("    netdns.work.                   900     DNSKEY  257 3 5 (
                                        AQOwktT7a2gfGNXWK+QWKP/Lln5Z/fSz0q2f
                                        R1fA4QBQsWsrnKz/yqXRmOHhf8X975ZVwpdo
                                        456wYjbfrP03sSjI3Wj9y5Mnr09HUUaBdwF/
                                        7VVgpP8Mgwe3FJ4f2uPwBFm2/+7+wxMyjIbL
                                        mu0Ec6xtZtEARe99RLnRCnF1gXb6Uw==
                                        ) ; key id = 17895");



my $bindsig=Net::DNS::RR->new("netdns.work.  900     RRSIG   DNSKEY 5 2 900 20350101000000 (
                                        20040121160223 17895 netdns.work.
                                        SUENn9MMZd9PPdtt//rbMbCgI7XGAmvb4QWO
                                        6Zuwis3ErhZR5PdiQNqhY53pN44Dnq5Qv4CO
                                        nIpoFLMZKpT1W/8jNFHZI8wX63hn8kYDUW9C
                                        lJt2YlovakAo3tMR3L/QvbkentB3ljJVEMYF
                                        PwJCmzS64bXNr960ZlOfnKY4Yl8= )");



my    $binddataset=[$bindkey];





my $nxtrr=Net::DNS::RR->new("example.com  7200    NSEC    bert.example.com. NS SOA MX TXT LOC RRSIG NSEC DNSKEY");



ok ( $nxtrr, 'NXT RR created from string');		#test 27

my $nxtsig=Net::DNS::RR->new("example.com  7200    RRSIG   NSEC 5 2 7200 20310101000000 (
                                        20040126131948 37790 example.com.
                                        IFK3Y4xZwkyHP0TwMnsC7g2IvHRZmsk8rFH7
                                        l1dM7Jyb7+p2Mh1nm13vv56sBOItHNDGvQtN
                                        yVDNuG2brf0zpHLHSzB/KsW1NNLTrTCscK1W
                                        0JNu2WwiZo62dZLQqIY4RQqTsWxf17c0f3aA
                                        w8ogGRXVnHwv0uGKRfMnWpX2AgA= )");

my $nxtkey=Net::DNS::RR->new("example.com                        900     DNSKEY  256 3 5 (
                                        AQOzkktb0iNYIj9GuasRjJixkK/YZ5eAe/Hs
                                        anvfZ7023ZPmEdNvRfygmCRDOFs0ud7J8u8n
                                        YnWn9EBxxS4AKSj8To+Dtx+vuW/g72SQjbNZ
                                        T3EGlwU3F2455qUAkAd4CADVMcbbLO0MbXRk
                                        /fd+Mq8A1zdX8q602fdaxaZ325nE0Q==
                                        )");


my @nxtdata=($nxtrr);



SKIP: {
    skip "Test material not available yet, will be fixed in later release", 2 if 0;
    ok( $bindsig->verify($binddataset,$bindkey),
	'RSA sig generated with bind verifies');        #test 29
    ok( $nxtsig->verify(\@nxtdata,$nxtkey), "RRSIG over NXT verifies");   #test 29
}


#
# RSA keypair 
#
my $keypathrsasha1="Ktest.tld.+005+42495.private";
my $privrsakeysha1= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 5 (RSA-SHA1)
Modulus: ovtC5gQH1fuAnQqMvNctGfX3o2F82164fO7toGiWddiLTuWxrXoHwcpIFLO+hJR9Xxr1gaWh6od66CJnOzBpIQjIe/htpRO2nmLFF5+cB3QRRMGQWmq3bPCXDBHE/Jx8ihzWZavXwIUN+oLqhnWbkT6sYGH8M+9VSW9rfeil/+c=
PublicExponent: Aw==
PrivateExponent: bKeB7q1ajqerE1xd0zoeEU6lF5ZTPOnQU0nzwEW5o+WyNJkhHlFagTGFYyJ/Aw2o6hH5ARkWnFpR8BbvfMrwv6AeCrahtJgilCpCYxwusOOikbkGR/sXP5ObscRmEuhfzVYBV62yMc34MyspHzXHNZAL+SgRswopy6MgWdAII2s=
Prime1: 0GNRLAYLvgaIZ+8o/fVST6WEhQd4bDIEHnBtIxHj9NIrHL/nIerA80sth+Pwfed2zp109U+zvcizUSfJDbHRsQ==
Prime2: yDgaunUKcXw3u3JZ92Crzvflpv92BeKJdL0USBn8Sxqq/xR7BWG03M6AOkjnJwlKF/z1sJHzok3kqZMuIuf5Fw==
Exponent1: iuzgyAQH1ARa7/TF/qOMNRkDA1pQSCFYFErzbLaX+IwcvdVEwUcrTNzJBUKgU++kib5N+N/NKTB3i2/bXnaLyw==
Exponent2: hXq8fE4G9lLP0kw7+kByifqZGf+kA+xboyi4MBFS3Lxx/2L8rkEjPd8AJttExLDcD/35IGFNFt6YcQzJbJqmDw==
Coefficient: gAeUUI6YOtdNAh3kS7pOzYfn0ZrUCV8bGpZoaXANk2RL2zUiaSSa4wudhpHwMJt+psNkkiQyf4v600uHbxro4Q==
ENDRSA

my $rsasha1keyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 5 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok( $rsasha1keyrr, 'RSA-SHA1 public key created');     #test 30


open (RSA,">$keypathrsasha1") or die "Could not open $keypathrsasha1";
print RSA $privrsakeysha1;
close(RSA);



my $sigrsasha1= create Net::DNS::RR::RRSIG($datarrset,$keypathrsasha1, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));



ok ( $sigrsasha1, 'RSA SHA1 signature created');                               #test 31


ok ($sigrsasha1->verify($datarrset,$rsasha1keyrr),'RSA SHA1 sig verifies');        #test 32


### Test usability of the private key object.. same set of test as above


my $dsaprivate=Net::DNS::SEC::Private->new($keypathdsa);

my $dsasigrr_p=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $dsaprivate
				    );
ok( $dsasigrr_p, 'DSA signature with bind generated key ');             # test 33

my $rsaprivate=Net::DNS::SEC::Private->new($keypathrsa);
my $rsasigrr_p=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $rsaprivate
				    );
ok( $rsasigrr_p, 'RSA signature with bind generated key');            # test 34


ok( $dsasigrr_p->verify($nldatarrset,$dsakeyrr),'DSA sig (test 2) verifies');       # test 35

is( $dsasigrr_p->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    # test 36

ok( $rsasigrr_p->verify($nldatarrset,$rsakeyrr),'RSA sig (test 2) verifies');       

is( $rsasigrr_p->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    # test 38












unlink($keypathrsa);
unlink($keypathdsa);
unlink($keypathrsasha1);







