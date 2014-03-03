#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 11-sigstress.t 1171 2014-02-26 08:56:52Z willem $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 


use constant LOOPS=>50;
use Test::More tests=> (LOOPS * 9 + 3 ); # 3 tests befor the loop, 9 inside.
use strict;

use Net::DNS::SEC;

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
open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
print RSA $privrsakey;
close(RSA);



my $keypathrsasha1="t/Ktest.tld.+005+32972.private";
my $privrsasha1key= << 'ENDRSASHA1' ;
Private-key-format: v1.2
Algorithm: 5 (RSASHA1)
Modulus: mI5MpW3OGQbD3X9aW9xCYbeKeyXh+NTOL1vts93rKuyq/cLIZsrJVG5LZlWHa7kEL3I1c0qj3fPZww6HRWtJeDZlSC3U81XeTE4z1vlJHYITiiLcyqUX1qK3/CGKeU6OlvhDL6mglshW2pPvKEs/SWEIRLP0/gahH0fJ1SAVfq8=
PublicExponent: Aw==
PrivateExponent: ZbQzGPPeu1nX6P+RkpLW68+xp26WpeM0H5Ked+lHcfMcqSyFmdyGOEmHmY5aR9CtdPbOTNxtPqKRLLRaLkeGTxyyxxapT8seZu5+r+Xniq+F+iHFG9nvQW+gB03WRvLJUf//mDKt7qBnXRVTqh51BXMQR5S80afmFMEFf8Q3hMs=
Prime1: yjowRynvf+0mtTXljuFkKvq0xYNlts5ArRhSNV4+HRcSHCjrMGwbkJKQIhU38JxaVUPsBp8WA+geGxZCxBUXNw==
Prime2: wR7tRK0MJUOLMz/pkYxpT8/eKrG7J2Kzzi+e92rQxUmJ3BrgLS+VRyk+0dxxLPNm3yvtTjqtht/iCytSta0gSQ==
Exponent1: htF1hMafqp4ZziPuX0Dtcfx4g6zued7VyLrheOl+vg9haBtHdZ1ntbcKwWN6oGg8ONfyrxS5V/AUEg7XLWNkzw==
Exponent2: gL9I2HNdbi0Hd3/xC7Lw39/pccvSGkHNNB+/T5yLLjEGkryVc3UOL3DUi+hLc0zvP3KeNCceWeqWshzhznNq2w==
Coefficient: XST5nq13vpLpNiATuLDRWc5HvJfrZ6qw2qYgKBJ635Fye4N8XUM9Gxm1DxVrhJnSjER4r7WgqMmcnJyP39VCAw==
ENDRSASHA1


my $rsasha1keyrr=new Net::DNS::RR ("test.tld. IN DNSKEY 256 3 5 AQOYjkylbc4ZBsPdf1pb3EJht4p7JeH41M4vW+2z3esq7Kr9wshmyslU bktmVYdruQQvcjVzSqPd89nDDodFa0l4NmVILdTzVd5MTjPW+UkdghOK ItzKpRfWorf8IYp5To6W+EMvqaCWyFbak+8oSz9JYQhEs/T+BqEfR8nV IBV+rw==");



ok( $rsasha1keyrr, 'RSASHA1 public key created');     # test 2
open (RSASHA1,">$keypathrsasha1") or die "Could not open $keypathrsasha1";
print RSASHA1 $privrsasha1key;
close(RSASHA1);




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

ok( $dsakeyrr, 'RSA public key created');      # test 3


open (DSA,">$keypathdsa") or die "Could not open $keypathdsa";
print DSA $privdsakey;
close(DSA);


my $datarrset=[$dsakeyrr, $rsakeyrr, $rsasha1keyrr];



my $PrivateRSA=Net::DNS::SEC::Private->new($keypathrsa);
my $PrivateRSASHA1=Net::DNS::SEC::Private->new($keypathrsasha1);
my $PrivateDSA=Net::DNS::SEC::Private->new($keypathdsa);

for (my $i=0;$i<LOOPS;$i++){
	
    my $update_rsa = Net::DNS::Update->new("test.test");
    $update_rsa->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
    $update_rsa->sign_sig0($PrivateRSA);


    my $update_rsasha1 = Net::DNS::Update->new("test.test");
    $update_rsasha1->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
    $update_rsasha1->sign_sig0($PrivateRSASHA1);




    my $update_dsa = Net::DNS::Update->new("test.test");
    $update_dsa->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
    $update_dsa->sign_sig0($PrivateDSA);
    $update_rsa->data;
    $update_rsasha1->data;
    $update_dsa->data;
    my $sigrrsa=$update_rsa->pop("additional");
    my $sigrrsasha1=$update_rsasha1->pop("additional");

    my $sigrrdsa=$update_dsa->pop("additional");
    ok ($sigrrsa->verify($update_rsa, $rsakeyrr),'RSA SIG0 verification of packet data');
    is( $sigrrsa->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");

    ok ($sigrrsasha1->verify($update_rsasha1, $rsasha1keyrr),'RSASHA1 SIG0 verification of packet data');
    is( $sigrrsasha1->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");


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

    my $sigrsasha1= create Net::DNS::RR::RRSIG($datarrset,$keypathrsasha1, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));
    # Verify the just created signatures
    ok ($sigrsasha1->verify($datarrset,$rsasha1keyrr), 'DSA sig verifies');       




}

unlink($keypathrsa);
unlink($keypathrsasha1);
unlink($keypathdsa);


















