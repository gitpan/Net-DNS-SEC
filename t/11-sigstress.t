#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 11-sigstress.t 222 2005-03-04 09:03:31Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 


use constant LOOPS=>50;
use Test::More tests=> (LOOPS * 6 + 2 ); # 2 tests befor the loop, 6 inside.
use strict;

use Net::DNS;
use Net::DNS::RR::SIG;

########
####   Couple of SIG0 and RRSIG tests


diag("This may take a while, do not worry.");


#
# RSA keypair 
#
my $keypathrsa="t/Ktest.tld.+001+42495.private";
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



ok( $rsakeyrr, 'RSA public key created');     # test 1




my $keypathdsa="t/Ktest.tld.+003+09734.private";
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

ok( $dsakeyrr, 'RSA public key created');      # test 2


open (DSA,">$keypathdsa") or die "Could not open $keypathdsa";
print DSA $privdsakey;
close(DSA);


my $datarrset=[$dsakeyrr, $rsakeyrr];



my $PrivateRSA=Net::DNS::SEC::Private->new($keypathrsa);
my $PrivateDSA=Net::DNS::SEC::Private->new($keypathdsa);

for (my $i=0;$i<LOOPS;$i++){
	
    my $update_rsa = Net::DNS::Update->new("test.test");
    $update_rsa->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
    $update_rsa->sign_sig0($PrivateRSA);

    my $update_dsa = Net::DNS::Update->new("test.test");
    $update_dsa->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
    $update_dsa->sign_sig0($PrivateDSA);
    $update_rsa->data;
    $update_dsa->data;
    my $sigrrsa=$update_rsa->pop("additional");

    my $sigrrdsa=$update_dsa->pop("additional");
    ok ($sigrrsa->verify($update_rsa, $rsakeyrr),'RSA SIG0 verification of packet data');
    is( $sigrrsa->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");
    ok ($sigrrdsa->verify($update_dsa, $dsakeyrr),'DSA SIG0 verification of packet data');
    is( $sigrrdsa->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");
    

    my $sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));
    # Verify the just created signatures
    ok ($sigdsa->verify($datarrset,$dsakeyrr), 'DSA sig verifies');       


    my $sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));
    # Verify the just created signatures
    ok ($sigrsa->verify($datarrset,$rsakeyrr), 'DSA sig verifies');       





}

unlink($keypathrsa);
unlink($keypathdsa);


















