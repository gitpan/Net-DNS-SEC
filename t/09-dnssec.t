#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 09-dnssec.t,v 1.4 2002/09/26 07:16:33 olaf Exp $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 

use Net::DNS::RR::SIG;

use Test::More tests=>40;
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
# In the following tests we first sign a KEY and then verify it again.
# We do this for both RSA and DSA.
# This is a consistency check 
# 
# The private key will be written to disk first.
#
# Keypairs generated with dnssec-keygen. (9.2.0rc1)


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

# Create the signature records.

my $sigrsa= create Net::DNS::RR::SIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature created');                               # test 7

my $sigdsa= create Net::DNS::RR::SIG($datarrset,$keypathdsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));
ok ( $sigrsa, 'DSA signature created');                               # test 8



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

$rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfA 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok (!$sigrsa->verify($datarrset,$rsakeyrr),'RSA fails agains corrupt key');
                                                                     # test 13

$dsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 3 
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


ok (! $sigdsa->verify($datarrset,$dsakeyrr),'DSA fails agains corrupt key');
                                                                     # test 14


# Now test some DSA stuff
my $keyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");

my $dsrr=create Net::DNS::RR::DS($keyrr);
ok( $dsrr,'DS created from KEY RR');                                # test 15


ok( $dsrr->verify($keyrr),'DS matches KEY');                        # test 16



my $dsrr2=Net::DNS::RR->new("test.tld.	0	IN	DS	42495  1  1  0ffbeba0831b10b8b83440dab81a2148576da9f6");


ok( $dsrr,'DS(2) created from string');                              # test 17


ok( $dsrr->verify($keyrr),'DS(2) matches KEY');                      # test 18



my ($nlkey1, $nlsig1, $nlNS1, $nlNS2, $nlNS3, $nldatarrset);

    $nlNS1=new Net::DNS::RR(" host100.ws.disi.  600   IN A    10.1.1.100");
    $nlNS2=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.2.100");
    $nlNS3=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.3.100");
    $nldatarrset=[$nlNS1,$nlNS3, $nlNS2];

my $dsasigrr=Net::DNS::RR::SIG->create($nldatarrset,
				    "t/Ktest.+003+39002.private"
				    );



ok( $dsasigrr, 'DSA signature with bind generated key');             # test 19


my $rsasigrr=Net::DNS::RR::SIG->create($nldatarrset,
				    "t/Ktest.+001+40320.private"
				    );
ok( $rsasigrr, 'RSA signature with bind generated key');            # test 20



my $dsakeyrr2=Net::DNS::RR->new("test. IN KEY 256 3 3
 CP+sp4HfN6oGZOmXdY1D4Rq82lsbj+WtB5i2sZGdatiRmZ5WJakUzdrq
 Id4FAohZn3msK1BVBjBNABO+rf1m/8/8OJiVvxSlE20B0bKpMHxAwNxI
 Qwq6c1Niky2mvsKoE8cNZG7GKNX6vCE/PSmN+G23BsvMLJJob3W4XbJ6
 mKiUy1LloBJpvjcKv0ybhnAhwM38owlILI8izfO4dlDJIWx+Esfg3zt5
 uwqEdzFv0uWeUxuKU55hudP3ZD5zm5qBov7vLSxSLHnomlM6yPFB3LC3
 SntWAGfDB7Kzfxg4UWlVjokDlQViHImWuB19oKShjCnsIM67RoL4L4bI
 etwtNiZ/GPJlnxtsWuYKdH7SFG4cB2oZqljtLAhEm1vmf8S/ZRRg1xg5
 yiwywekS5tYU7lGPjXdqxZUdaDfgzaehZPmbecQI722n8B3E1fMEF71E
 /ejkUlZDaVTgk8bCsdXljNfS4W+IMUny69YTloB/kBBy8Al51psV7AJm
 gMku/iw5Aa8jhEnVqBtv5/kqEFuKE8iCyou8");

my $rsakeyrr2=Net::DNS::RR->new("test. IN KEY 256 3 1
 AQO6bG+OUEhiT2rU5+3q8S2TX+Q+J9DEpyX5rZKnQ/JU2Z558PEsxqb2
 D8lSLoOtfB/RSgoGQqKGTr6QxbLvyE8vkm/A0QD8Tk9MAm30P9AwIo1c
 HDjgwyRYWYEE0xfLCj+hAOXK3ltgc6a9lpoNFO/3NqtXapJoJErYMLOH
 H52ARQ==");


ok( $dsasigrr->verify($nldatarrset,$dsakeyrr2),'DSA sig (test 2) verifies');       # test 21

ok( $rsasigrr->verify($nldatarrset,$rsakeyrr2),'RSA sig (test 2) verifies');       # test 22







########
####   Couple of SIG0 tests





my $update1 = Net::DNS::Update->new("test.test");
ok ( $update1, 'Creating Update packet 1' );                      #test 23

$update1->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
$update1->sign_sig0("t/Ksigzero.+001+39700.private");
my $keyrr1=Net::DNS::RR->new("sigzero. IN KEY 512 3 1 
 AQOsBkYa41HLlNPoiWj5Ixhl/E+MI9HHlnVWWD/HrsqMwnzour36oQe0
 ZqG10H7m/lX852h5EgLci/G/7ePPwpwX5aPK0rAa0NMZOuWzrYvi5Cfb
 nMMJoCKhPDAqQ/tSkWrAYOMg1yKqbPcdD7Iiaax+IepVe2PWqHkiSiYg
 N5sUdw==");

ok ($keyrr1,'RSA Public key for SIG0');                            #test 24

my $update2 = Net::DNS::Update->new("test.test");
ok ( $update2, 'Creating Update packet 2' );                       #test 25

$update2->sign_sig0("t/Ksigzero.+003+08890.private");

my $keyrr2=Net::DNS::RR->new("sigzero. IN KEY 512 3 3 (
 CLTNO98RRjOTJava4IA2BH3xht5d+iSKa/5QxX2AHa4J5IAz7ELy8ZEV 
 pXuA1EE70bkpcGHoa4JowHpZLGm53ZiEIBL7JyKoF0AXCxJt8X+jfpIl 
 K4ZgWN3uBgLBn1nDWfgjeNc+8prXeeO6ESM5Elf0dYyM3ZfqSzCaxreM
 +UIBSjOtO3UqTvnPr55vhP15+1BxFOlJRYXu3pD9AxdvqSNFEmN1BFyr
 R+8kg2i/wUu8kC2iFdl/VSKls1vDxB/F2tqwX/OHx7iRKJKwih5RPo0G
 ok2V6lJ4Va4Ne0dQq//W0lVFqq15ZgcYnxH8TuH9LVxtzop28XL2p/BX
 Hew2SCgzy1hUeun/PyP1JDbGCRFTkBDP5JbrFAUEBgF+GWSDhTESo4L2
 w9DlGruC//hodRPyrvrskNHjDNGeR2v9u8XTraO0kXex8GMWUikU/miA
 OdSeRHcdIibueh/wGLvAV7AXVgJJrgZNDHXZhlWjjRvMlqZu9UuYKL4R
 jOmEwwie7JQxN7Ag3n9U2uBmR+LKcGyREby2");

ok ($keyrr2,'DSA Public key for SIG0');                             #test 26


$update1->data;
$update2->data;
my $sigrr1=$update1->pop("additional");
ok ($sigrr1,"Obtained RSA sig from packet");                        # test 27

my $sigrr2=$update2->pop("additional");
ok ($sigrr2,"Obtained DSA sig from packet");                        # test 28
ok ($sigrr1->verify($update1, $keyrr1),'RSA SIG0 verification of packet data');


                                                                    # test 29
ok ($sigrr2->verify($update2, $keyrr2),'DSA SIG0 verification of packet data');

                                                           # test 30

ok (!$sigrr1->verify($update2, $keyrr1),'RSA SIG0 fails with invalid data');
                                                                    # test 31
ok (!$sigrr2->verify($update1, $keyrr2),'RSA SIG0 fails with invalid data');
                                                                    # test 32


#
# SOA with escaped dot.
$datarr1 = Net::DNS::RR->new("test.tld.	7000	IN	SOA (
			     ns.test.tld.
			     first\.last.test.tld. 
			     2002042603 43200 7200 1209600 7200)");

$datarrset = [ $datarr1 ] ;
$sigrsa= create Net::DNS::RR::SIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature over SOA with escaped dot  created');                # test 33
$rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");

ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA sig over SOA  with escaped dot verifies');        # test 34



# clean the private key files (not needed no more)
unlink($keypathrsa);
unlink($keypathdsa);



# Cross check with a  signature generated with bind tools.
# Test fails after October 2030 :-)

my $bindkey=Net::DNS::RR->new("test.foo       3600         IN KEY  256 3 1  (
                              AQPDgM2XU2rluutXFw6IJjDRSGHehcc1ZtMoG5RR/
                              jXJD1bZNFgqsKlJkVfj9wzrzAnBg7ZQSHwxYIGDm
                              ocdBtW3 )");


my $bindsig=Net::DNS::RR->new("test.foo        3600        IN  SIG     (
                               KEY 1 2 3600 20300101000000  
                               20020523123523 1749 test.foo. 
                               YUf+2kUnz3bMCfRJyraFTxcmiTCMiGkfvwaeLa8oXzJX  
                              PUfCpYzJUb9lH7/J4H8hk+Yg2RU81s423IFs155Yag== )");


my    $binddataset=[$bindkey];

ok( $bindsig->verify($binddataset,$bindkey),
    'RSA sig generated with bind verifies');        #test 35




my $nxtrr=Net::DNS::RR->new("sub.tld.		100	IN	NXT	b1.sub.tld. NS SOA SIG KEY NXT");

ok ( $nxtrr, 'NXT RR created from string');		# test36

my $nxtsig=Net::DNS::RR->new("sub.tld.		100	IN	SIG	NXT 1 2 100 20300627095441 20020814112311 23495 sub.tld. dGES80B4hlMUq7rS5etQ03emiq+y9gchIc/VO650PE3ssSJMcELzl9T2 /RiKOs5plEGl+iyHpo0XTSW0oEi8D4SX/4vXHpE5PHK2ME/40JW8ULT7 DEI+zmqmcZnvMKCktysKMLcSa6nLo8AOtEa/FtiIYes7r9Ff6tCydryC 4Qg=");

my $nxtkey=Net::DNS::RR->new("sub.tld.		100	IN	KEY	256 3 1 AQPw02b9MnR8aJplOyI1CB0u1zBGi9xFAPiZ1NkdDlqne3lSXpGHzQNT hf16EIdk+diCroSOFdz3jA/0fnHbG80wQ35k2YvVVqooHHel9nAeMHJF SgAzgV2Ht7hOnagaK0V4zbcvDnHm6kyiPuLExvknehLg6G9b+yNtZJ0g g1vHGQ==");


my @nxtdata=($nxtrr);

ok( $nxtsig->verify(\@nxtdata,$nxtkey), "SIG over NXT verifies");   #test37

0;











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

my $rsasha1keyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 5 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok( $rsasha1keyrr, 'RSA-SHA1 public key created');     # test 38


open (RSA,">$keypathrsasha1") or die "Could not open $keypathrsasha1";
print RSA $privrsakeysha1;
close(RSA);



my $sigrsasha1= create Net::DNS::RR::SIG($datarrset,$keypathrsasha1, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));



ok ( $sigrsasha1, 'RSA SHA1 signature created');                               # test 39


ok ($sigrsasha1->verify($datarrset,$rsasha1keyrr),'RSA SHA1 sig verifies');        # test 40

unlink($keypathrsasha1);
