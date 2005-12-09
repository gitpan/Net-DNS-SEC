#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 09-dnssec.t 526 2005-12-08 15:19:04Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 


use Net::DNS::RR::RRSIG;

use Test::More tests=>72;
use strict;


BEGIN {
  use_ok('Net::DNS'); 
}                                 



my $datarrset;
my ($datarr1, $datarr2, $datarr3);
my $datastring1="test.tld.		7000	IN	NS	ns.test.tld.";
my $datastring2="test.tld.		7000	IN	NS	ns.foo.tld.";
my $datastring3="test.tld.		7000	IN	NS	ns.boo.tld.";

my $otherrrset;
my ($otherrr1, $otherrr2, $otherrr3);
my $otherstring1="*.test.tld.		7000	IN	TXT	cruft";
my $otherstring2="*.test.tld.		7000	IN	TXT     more cruft.";
my $otherstring3="*.test.tld.		7000	IN	TXT	last cruft";



$datarr1=  new Net::DNS::RR($datastring1);
ok ( $datarr1, 'data RR 1 loaded ');                         
$datarr2=  new Net::DNS::RR($datastring2);
ok ( $datarr2, 'data RR 2 loaded ');                         
$datarr3=  new Net::DNS::RR($datastring3);
ok ( $datarr3, 'data RR 3 loaded ');                         
$datarrset = [ $datarr1, $datarr2 , $datarr3  ] ;




$otherrr1=  new Net::DNS::RR($otherstring1);
ok ( $otherrr1, 'other RR 1 loaded ');                         
$otherrr2=  new Net::DNS::RR($otherstring2);
ok ( $otherrr2, 'other RR 2 loaded ');                         
$otherrr3=  new Net::DNS::RR($otherstring3);
ok ( $otherrr3, 'other RR 3 loaded ');                         
$otherrrset = [ $otherrr1, $otherrr2 , $otherrr3  ] ;




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
my $keypathrsa="Ktest.tld.+001+50399.private";
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


open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
print RSA $privrsakey;
close(RSA);


my $rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");



ok( $rsakeyrr, 'RSA public key created');     




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
8VNN/RPQNkZOg6fRLtKF7DPIXFFJ0b+npMnA


");

ok( $dsakeyrr, 'RSA public key created');      



open (DSA,">$keypathdsa") or die "Could not open $keypathdsa";
print DSA $privdsakey;
close(DSA);

# Create the signature records.

my $sigrsa= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));


ok ( $sigrsa, 'RSA signature created');                               

is ( $sigrsa->ttl, 360, "TTL from argument");

my $sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa);
ok ( $sigdsa, 'DSA signature created');                               

is ( $sigdsa->ttl, 7000, "TTL from RRset");

# Verify the just created signatures
ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA sig verifies');        
# Verify the just created signatures
ok ($sigdsa->verify($datarrset,$dsakeyrr), 'DSA sig verifies');       

# on the other hand checking against the wrong key should fail.
ok (! $sigrsa->verify($datarrset,$dsakeyrr), 
    'RSA sig fails agains corrupt data');                             

ok (! $sigdsa->verify($datarrset,$rsakeyrr),
    'DSA sig fails agains corrupt data');                             




my $othersigrsa= create Net::DNS::RR::RRSIG($otherrrset,$keypathrsa, 
				    (
				     ttl => 360, 
				     ));

is($othersigrsa->labels,2,"Correct label count in presence of asterisk label");


# Now corrupt the key and test again.. that should fail
# Corruption is very hard to notice.. we modified one letter
# in the base 64 representation.

my $corrupt_rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfA 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t9 
6KX/5w==");


ok (!$sigrsa->verify($datarrset,$corrupt_rsakeyrr),'RSA fails agains corrupt key');
                                                                     

my $corrupt_dsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 3 
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
                                                                     


# Now test some DSA stuff

my $dsrr=create Net::DNS::RR::DS($rsakeyrr);
ok( $dsrr,'DS created from KEY RR');                                


ok( $dsrr->verify($rsakeyrr),'DS matches KEY');                        



my $dsrr2=Net::DNS::RR->new("test.tld.	0	IN	DS	
                             42495  1  1  
                             0ffbeba0831b10b
                             8b83440dab81a2148576da
                             9f6");


is ($dsrr2->digest,"0ffbeba0831b10b8b83440dab81a2148576da9f6","Digest read correctly"); 
                                                                     
ok( $dsrr,'DS(2) created from string');                              


ok( $dsrr->verify($rsakeyrr),'DS(2) matches KEY');                      



my ($nlkey1, $nlsig1, $nlNS1, $nlNS2, $nlNS3, $nldatarrset);

    $nlNS1=new Net::DNS::RR(" host100.ws.disi.  600   IN A    10.1.1.100");
    $nlNS2=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.2.100");
    $nlNS3=new Net::DNS::RR("host100.ws.disi.  600   IN A    10.1.3.100");
    $nldatarrset=[$nlNS1,$nlNS3, $nlNS2];

my $dsasigrr=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathdsa
				    );
ok( $dsasigrr, 'DSA signature with bind generated key');             


my $rsasigrr=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathrsa
				    );
ok( $rsasigrr, 'RSA signature with bind generated key');            



ok( $dsasigrr->verify($nldatarrset,$dsakeyrr),'DSA sig (test 2) verifies');       

is( $dsasigrr->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    

ok( $rsasigrr->verify($nldatarrset,$rsakeyrr),'RSA sig (test 2) verifies');       

is( $rsasigrr->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    

########
####   Couple of SIG0 tests

my $update1 = Net::DNS::Update->new("test.test");
ok ( $update1, 'Creating Update packet 1' );                      

$update1->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
$update1->sign_sig0($keypathrsa);

ok ($rsakeyrr,'RSA Public key for SIG0');                            

my $update2 = Net::DNS::Update->new("test.test");
ok ( $update2, 'Creating Update packet 2' );                       

$update2->sign_sig0($keypathdsa);


ok ($dsakeyrr,'DSA Public key for SIG0');                             


$update1->data;
$update2->data;
my $sigrr1=$update1->pop("additional");
ok ($sigrr1,"Obtained RSA sig from packet");                        

my $sigrr2=$update2->pop("additional");
ok ($sigrr2,"Obtained DSA sig from packet");                        
ok ($sigrr1->verify($update1, $rsakeyrr),'RSA SIG0 verification of packet data');


                                                                    
ok ($sigrr2->verify($update2, $dsakeyrr),'DSA SIG0 verification of packet data');

                                                           

ok (!$sigrr1->verify($update2, $rsakeyrr),'RSA SIG0 fails with invalid data');
                                                                    
ok (!$sigrr2->verify($update1, $dsakeyrr),'RSA SIG0 fails with invalid data');
                                                                    


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


ok ( $sigrsa, 'RSA signature over SOA with escaped dot  created');                


ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA sig over SOA  with escaped dot verifies');        



# clean the private key files (not needed no more)



# Cross check with a  signature generated with bind tools.


my $bindkey=Net::DNS::RR->new(" foo.example                        3600    DNSKEY  256 3 5 (
                                        AQMLaOdD3VKofLiblKFdjnJpVFPD1mbIxh2H
                                        +JaHkblnFH5cKn/mHU21ODD4mubkPqrhpEWi
                                        Omm5+rpj90YdeFilf05tncc+3vr3ttSKKpXz
                                        nV1h+IuX4tUwnCd1xH8+FrvoSJLgFCR97VG7
                                        wwKOIXjjttpnoj+eX8wnlR0u8DxXH8q7o2Un
                                        o5T1htoz/RtjUdbkuTpn4a7XRt98GcBQ1YGd
                                        iOk3c5sVSCqHeEpsHTSSa5DYcNbBD71d+ahc
                                        jkKVJXyAGRNEjEvYRQ6XSQ84rH7okO3Pl18V
                                        rBDEMw6mivD0970W/Y0T2nBORTDR7h9D/62+
                                        SmqCxuW6ISPvhL8VgO9R64i9/vo3K95JIEQB
                                        LH+dab2olsuM+O9rVkBaIe+qNT6hT0ScRR6E
                                        eDdA0CH+zqATqGrENT6I4XES+tuVJKK6Cph5
                                        L3uO5QeevoFgh3jJDKHawi/QA2P0mhtTNF1E
                                        Q7XwlHZVefVxUmLjJ5r7UBKaa7xAg8W4RKCR
                                        9w==
                                        ) ; key id = 43787
");


my $bindsig=Net::DNS::RR->new("foo.example    3600    RRSIG   (
                                        DNSKEY 5 2 3600 20320101000000 
                                        20050330103924 43787 foo.example.
                                        BfAfvJtmvnhxMTo6frGc7bSNJS0M5D6zWBK3
                                        WSoeYtDEyLhNDJSNL34lVlR8zkuKOLZ0b3mU
                                        duscHd5f/AVb5mhVjmAGIIY4LWv9WIJlGBAG
                                        mzlsYpx/fNWk8er55bSy5XRDB/46uIfTGVFs
                                        4gjO39HgNOEH8IniuBvTvdK8/KhSZUlru1FP
                                        Hzo2n+Jxv3weiVm1Q+bUBjJoX8GZ9sPeC83s
                                        JHA8BhGwbvUIOCZUaFUwF5cREJUvyK32Uc+L
                                        qIgJOWlCgkCOBDjLmnsKrIQ085ymJAIK2M8k
                                        65e7+IrsysNZSBLoEeVaDZn0/AoYpoOnphCw
                                        ibTt2ETYR4rgdO2Ffqzot9ZkSSnjZ5FwNmmS
                                        rthYddYAofScUX/5rtHYeLPk1D6iTcQGmdeu
                                        HY/7YgkrjaPRAwZ8SW9H4Ud78kFmVBLfIFRj
                                        df7O4KRmQdufVpoFb7fOy1c/JtmnZp3kQZuw
                                        vrAyfMJK5QXD1TM1CYFFeF2gyCRNzhv2sDQ= )



");


my    $binddataset=[$bindkey];

ok( $bindsig->verify($binddataset,$bindkey),
    'RSA sig generated with bind verifies');        




my $nsecrr=Net::DNS::RR->new("foo.example.			300	NSEC	foo.example. SOA RRSIG NSEC DNSKEY");

ok ( $nsecrr, 'NSEC RR created from string');		

my $nsecsig=Net::DNS::RR->new("foo.example.   300   RRSIG  (
					NSEC 5 2 300 20320101000000 
					20050330103924 43787 foo.example.
					CF3JXoyzhdi0hNj4gsEz+a8u8LedRrFtZpDc
					gvwdsQLYD+UTFEE/zbomMBxdh1M5EsVAnead
					5vTn1AeSvbBzy976FoAd6lDYEGgUvCEJUsng
					UHiCvBX6Netnqo4d7Tnzi0wsCvtAIMYuYa/T
					3FnLMaJepNKp+QctcO8RpjlLb+b8rNAxsNcv
					SaBxwAhPDvqQfPGmMQr5+Ga1c/1QCCkDyMzX
					sZ0YqzZgeU+9kkqent4hPBdI8vlsISpTZgmC
					BmNniBpPwpAHSAqCM0EyKu9Jni2laYT7Xsu2
					LpQ2NU6lYRfOVu/OG98IevFZZ90YHbvF84e8
					rHWllbuFLTien++AQitKCM9wxSPIoOFXq3O4
					pEV00Ja9UAQMvHtRiC5AronayV8fSRjooiJe
					67eLFYSV6t3K1Qlx4nKuTbM+9TFevvgWKk6w
					a6hHetCohec/7xTftU9R329Jm9fWQCrOLuYa
					gOKAKiwn8AtOTKyJec0wC2/lqrlMcToYtIM= )



");

my $nseckey=Net::DNS::RR->new("foo.example.   3600	DNSKEY	256 3 5  (
					AQMLaOdD3VKofLiblKFdjnJpVFPD1mbIxh2H
					+JaHkblnFH5cKn/mHU21ODD4mubkPqrhpEWi
					Omm5+rpj90YdeFilf05tncc+3vr3ttSKKpXz
					nV1h+IuX4tUwnCd1xH8+FrvoSJLgFCR97VG7
					wwKOIXjjttpnoj+eX8wnlR0u8DxXH8q7o2Un
					o5T1htoz/RtjUdbkuTpn4a7XRt98GcBQ1YGd
					iOk3c5sVSCqHeEpsHTSSa5DYcNbBD71d+ahc
					jkKVJXyAGRNEjEvYRQ6XSQ84rH7okO3Pl18V
					rBDEMw6mivD0970W/Y0T2nBORTDR7h9D/62+
					SmqCxuW6ISPvhL8VgO9R64i9/vo3K95JIEQB
					LH+dab2olsuM+O9rVkBaIe+qNT6hT0ScRR6E
					eDdA0CH+zqATqGrENT6I4XES+tuVJKK6Cph5
					L3uO5QeevoFgh3jJDKHawi/QA2P0mhtTNF1E
					Q7XwlHZVefVxUmLjJ5r7UBKaa7xAg8W4RKCR
					9w==
					) ; key id = 43787


");

my @nsecdata=($nsecrr);

ok( $nsecsig->verify(\@nsecdata,$nseckey), "RRSIG over NSEC verifies");   

#
# RSA keypair 
#
my $keypathrsasha1="Ktest.tld.+005+29159.private";
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


ok( $rsasha1keyrr, 'RSA-SHA1 public key created');     


open (RSA,">$keypathrsasha1") or die "Could not open $keypathrsasha1";
print RSA $privrsakeysha1;
close(RSA);



my $sigrsasha1= create Net::DNS::RR::RRSIG($datarrset,$keypathrsasha1, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));



ok ( $sigrsasha1, 'RSA SHA1 signature created');                               


ok ($sigrsasha1->verify($datarrset,$rsasha1keyrr),'RSA SHA1 sig verifies');        
ok ($sigrsasha1->verify($datarrset,[$rsasha1keyrr]),'RSA SHA1 sig verifies for 1 element keyrr array');        

is($sigrsasha1->vrfyerrstr,"No Error","Correct Errorstring for keyrr array (0)");




# Corrupted versions of rsasha1keyrr
my $rsasha1keyrr2=new Net::DNS::RR ("test.tld. IN KEY 256 3 5 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t8 
6KX/5w==");


my $rsasha1keyrr3=new Net::DNS::RR ("test.tld. IN KEY 256 3 5 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t7
6KX/5w==");

# This keyrr has been carefully crafted to have the same keytag as
# rsasha1keyrr
my $rsasha1keyrr4=new Net::DNS::RR ("test.tld. IN KEY 257 3 5 
AQOi+0LmBAfV+4CdCoy81y0Z9fejYXzbXrh87u2gaJZ12ItO5bGtegfB 
ykgUs76ElH1fGvWBpaHqh3roImc7MGkhCMh7+G2lE7aeYsUXn5wHdBFE 
wZBaards8JcMEcT8nHyKHNZlq9fAhQ36guqGdZuRPqxgYfwz71VJb2t8
6KX/5w==");


ok ($sigrsasha1->verify($datarrset,
			[$rsasha1keyrr3,$rsasha1keyrr2,$rsasha1keyrr]),
    'RSA SHA1 sig verifies for 3 element keyrr array ');        

is($sigrsasha1->vrfyerrstr,"No Error","Correct Errorstring for keyrr array (1)");

ok (! $sigrsasha1->verify($datarrset,
			[$rsasha1keyrr3,$rsasha1keyrr2,$rsasha1keyrr4]),
    'RSA SHA1 sig fails for 3element keyrr array with broken keys');        

is($sigrsasha1->vrfyerrstr,"key 1: keytag does not match key 2: keytag does not match key 3:RSA Verification failed ","Correct Errorstring for keyrr array (2)");


ok (! $sigrsasha1->verify($datarrset,
			[$sigrsasha1,$rsasha1keyrr2,$rsasha1keyrr3 ]),
    'RSA SHA1 sig fails for 3element keyrr array with wrong object in array');        
is($sigrsasha1->vrfyerrstr,"key 1:You are trying to pass Net::DNS::RR::RRSIG data for a key key 2: keytag does not match key 3: keytag does not match ","Correct Errorstring for array with non-keyobject");

ok ( $sigrsasha1->verify($datarrset,
			[$sigrsasha1,$rsasha1keyrr2,$rsasha1keyrr ]),
    'RSA SHA1 sig validates for 3element keyrr array with wrong object in array');        



##


my $dsaprivate=Net::DNS::SEC::Private->new($keypathdsa);

my $dsasigrr_p=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $dsaprivate
				    );
ok( $dsasigrr_p, 'DSA signature with bind generated key ');             

my $rsaprivate=Net::DNS::SEC::Private->new($keypathrsa);
my $rsasigrr_p=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $rsaprivate
				    );
ok( $rsasigrr_p, 'RSA signature with bind generated key');            


ok( $dsasigrr_p->verify($nldatarrset,$dsakeyrr),'DSA sig (test 2) verifies');       

is( $dsasigrr_p->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    

ok( $rsasigrr_p->verify($nldatarrset,$rsakeyrr),'RSA sig (test 2) verifies');                                                                         

is( $rsasigrr_p->vrfyerrstr, "No Error", "vrfyerrstr eq No Error");    







########
####   Couple of SIG0 tests  repeated with the private key  object as input.

my $update1_p = Net::DNS::Update->new("test.test");
ok ( $update1, 'Creating Update packet 1' );                      

$update1_p->push("update", Net::DNS::rr_add("test.test.test 3600 IN A 10.0.0.1"));
$update1_p->sign_sig0($rsaprivate);


my $update2_p = Net::DNS::Update->new("test.test");
ok ( $update2_p, 'Creating Update packet 2' );                       

$update2_p->sign_sig0($dsaprivate);



$update1_p->data;
$update2_p->data;
my $sigrr1_p=$update1_p->pop("additional");
ok ($sigrr1_p,"Obtained RSA sig from packet");                        

my $sigrr2_p=$update2_p->pop("additional");
ok ($sigrr2_p,"Obtained DSA sig from packet");                        
ok ($sigrr1_p->verify($update1_p, $rsakeyrr),'RSA SIG0 verification of packet data');


                                                                    
ok ($sigrr2_p->verify($update2_p, $dsakeyrr),'DSA SIG0 verification of packet data');

                                                           

ok (!$sigrr1_p->verify($update2_p, $rsakeyrr),'RSA SIG0 fails with invalid data');
                                                                    
ok (!$sigrr2_p->verify($update1_p, $dsakeyrr),'RSA SIG0 fails with invalid data');
                                                                    

unlink($keypathrsa);
unlink($keypathdsa);
unlink($keypathrsasha1);







