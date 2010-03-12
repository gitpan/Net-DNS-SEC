#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 09-dnssec.t 847 2010-03-12 13:04:13Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/09-dnssec.t 


use Net::DNS::RR::RRSIG;

use Test::More tests=>83;
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
# RSA/SHA-1 keypair 
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


open (RSA,">$keypathrsa") or die "Could not open $keypathrsa";
print RSA $privrsakey;
close(RSA);


my $rsakeyrr=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");



ok( $rsakeyrr, 'RSA/SHA-1 public key created');     




#
# RSA/SHA-256 keypair 
#
my $keypathrsa256="Ktest.tld.+008+31374.private";
my $privrsakey256= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: qMM+u+1QBzYCm6PteHMyPhLBLwagdf3SfkPwWUcjdfpFHKssWWKIVHNOhaYJy/YqyTeVpG+Ij6SdSeh/QN9G/p8k4UYsvlr9G6aofgcHrVOS3xVMXK4iH6P4UTvoNBuX48wHWC9426MyODf3DcK2NxDSdnOfhpUBBvC3z3mTSrM=
PublicExponent: AQAB
PrivateExponent: YN0v9M2RUZI+jPbaJnh4Lgi1uTgkgZTebHqySYv7Xov3fy0Al41mkpJcT3mtxdPVWwj8axVZXJkvbmx0HdgJ9sx9SoF5HmF078O5y7yit78gbbOEKyGRlU7kfEQrQ6uHBO99LJVtr89KplW3qVKwgH2FBiAyI9dNkevebJ4R8AE=
Prime1: 3GiJfuE1kaPIH6TH+b0nmH+bCQ0a7egDVrPcLVh9ybENy3KbvkRy3MYgBXBt/Zv8QgtQA+esGIwSWzxurzp1Mw==
Prime2: xAO6HUsZibwUv3aX9F2oPH1YmeZpdOXIdBMN4RpibbRqs5TfKQy8281nW5dKcFG97K9jKVGv9HGgPSuBC7DUgQ==
Exponent1: iZrqXMCWBTtPshHal9y0X80rKdd4vJdhnjvkdpsMzWMwzZfcDEoHvDYlv7+VrAQ61bDiX82/8ANjYnq0T8obaQ==
Exponent2: htg9h/trFSrTZyfRv2VS4FImyrEM6UNOlDOrf6kj/253XRVUNCw0HE4BBaxdpElHi/TYFcvBbTthzdMI0p8SgQ==
Coefficient: pXn2+3pGnSRX9fDliY1msoLu8dLzzZaYzxKl8NDCaBfj8XJEs0Ix7iovG886LLoZ2bLAZkS+1ZbRfFr+1wbmqA==
ENDRSA


open (RSA,">$keypathrsa256") or die "Could not open $keypathrsa256";
print RSA $privrsakey256;
close(RSA);


my $rsakeyrr256=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");

ok( $rsakeyrr256, 'RSA/SHA-256 public key created');     




#
# RSA/SHA-512 keypair 
#
my $keypathrsa512="Ktest.tld.+010+04625.private";
my $privrsakey512= << 'ENDRSA' ;
Private-key-format: v1.2
Algorithm: 10 (RSASHA512)
Modulus: 8feFRviN7LXET8rIBgoePE1Aj4Rml4bIEe24UiqOKsf5rsYy+F3T2HEYszKhhVpXFje3cjbtLOCnKsrg2iT+QQn8PBrc9y/AZ6sdR+qdYICx4V/QoCrzaBWIE6CUB3m1ZeoMDwnadkMGpYKuMIyi+oO8qfdYhIiElTY9/ctR7gE=
PublicExponent: AQAB
PrivateExponent: 6wlwYNwXoJN/ubJUUemKLTEtQTtvHElEFoY/wTCtIElX87l60V7y5RAW2hqYYxy5807z1vIbuLgQKbUgbUX54ffwans1E5jcXetTAUxYmAZbJMHJNk48ssbp8Kipr58O4BC0Fdg8iiJuUu+t4qnDp6Vxy+L4I07U1sjiUd7SpQE=
Prime1: +6O0SL5Wg32Gd/oQOJchH0xojeltBVVeyayadY6dM14ygTk4kwm3+6V+lRMPHyzxzEyXDY7jV62yqxLY+0NumQ==
Prime2: 9ijoalqp0VafFvv7jfQFceMmszAlnwzoxekuCdwO7CfRDHG4OOB3HvR1B/Ndr2LShS5X5pIHd1uAxPFrCYcjqQ==
Exponent1: x74hG+DiIUuhUljPSWxFIWfwUj0oiaRDMkhs7sV+aMjrxAFcs/Jx9TFfcguH5FIzuNxOxrdWJEG/YeX7EC9teQ==
Exponent2: ea1Q7Tlxlcu2ifr2pn2Hr3rz50EWZ59O9H1Fx5PiQHOSDw+rW1oBJ+j4bHysw4QawcBdrNhkHmi5pyAao7QMOQ==
Coefficient: oEwXjm4z0dVIkNS08yDSgAj9QTZLoKjDfoO/bpLLUYh9WnwPu2Jc+1eMreVfbC0RHTohxEntUuZXsPR7Du+zEQ==
ENDRSA


open (RSA,">$keypathrsa512") or die "Could not open $keypathrsa512";
print RSA $privrsakey512;
close(RSA);


my $rsakeyrr512=new Net::DNS::RR ("test.tld. IN KEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w==
");

ok( $rsakeyrr512, 'RSA/SHA-512 public key created');     




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

ok( $dsakeyrr, 'DSA public key created');      



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

my $sigrsa256= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa256, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));

ok ( $sigrsa256, 'RSA signature created');                               

my $sigrsa512= create Net::DNS::RR::RRSIG($datarrset,$keypathrsa512, 
				    (
				     ttl => 360, 
#				     sigval => 100,
				     ));

ok ( $sigrsa512, 'RSA signature created');                               

is ( $sigrsa->ttl, 360, "TTL from argument");

my $sigdsa= create Net::DNS::RR::RRSIG($datarrset,$keypathdsa);
ok ( $sigdsa, 'DSA signature created');                               

is ( $sigdsa->ttl, 7000, "TTL from RRset");

# Verify the just created signatures
ok ($sigrsa->verify($datarrset,$rsakeyrr),'RSA/SHA-1 sig verifies');        
# Verify the just created signatures
ok ($sigrsa->verify($datarrset,$rsakeyrr256),'RSA/SHA-256 sig verifies');        
# Verify the just created signatures
ok ($sigrsa->verify($datarrset,$rsakeyrr512),'RSA/SHA-512 sig verifies');        
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
ok( $rsasigrr, 'RSA/SHA-1 signature with bind generated key');            


my $rsasigrr256=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathrsa256
				    );
ok( $rsasigrr256, 'RSA/SHA-256 signature with bind generated key');            


my $rsasigrr512=Net::DNS::RR::RRSIG->create($nldatarrset,
				    $keypathrsa512
				    );
ok( $rsasigrr512, 'RSA/SHA-512 signature with bind generated key');            


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

my $bindkey1=Net::DNS::RR->new("
example.com.				      3600 IN DNSKEY	257 3 5 (
		  AQPUiszMMAi36agx/V+7Tw95l8PYmoVjHWvOKxx/0iH8ZE3sdEqQncCe
		  Jg7IVQ+LNWSP9mT/B26eQb5WZ2IKFzNFQTMNi6um+yh3nytazwOwOx00
		  2VGnwpYwnUFV3bZ5BcgWC8wrUzVGgCVIvX+besZrIXMY60yriRqQqNGO
		  DnKo2T6zYewfCw4lYxRKYT6RqA0y8nJqyLRmeZ0nYP6uvDYjHEu7mqUf
		  XBzeZNMy3WgSCTbQoK/RaSR7adTgTe5t972c51Di7TCwxpDzCfAKuPPk
		  liBM9Z0x4gC0AZfO5Ma0p+dhf2k7wfl8m8xEOEMJITLooy88Nh+u2c9H
		  F1tw0naH ; key id = 40620
");
my $bindkey2=Net::DNS::RR->new("
example.com.				      3600 IN DNSKEY	256 3 5 
		  AQPaoHW/nC0fj9HuCW3hACSGiP0AkPS3dQFXDlEUjv1orbtx06TMmVKG
		  K5K564OSd6UCf4ZQEu2CMPSAUFGHEZuANKYGwZh0k/HeoVNeom1L3Nt4
		  tVLiGMzrPQskzeK8sr1NKgqFmckQllMWd0ob8Ud6nqeQLHvXQgv1iHX3
		  dpBIPLYbRCzueqC5k09APl25PgJjjreyRXrxodvoiiaLHpdL5NtM2S9e
		  ok2zmuRpYQSF1LTNfWwY9CkgL017Z/Zv00SbcoTM/eTXPqijGtUhh6UX
		  1gX89ybeyjtfcGbmTcB+I79NykZWoddO8zyzBXzzfFwtsAuryjQ/HFa5
		  r4mrbhkJ ; key id = 6227
");
my $bindsig=Net::DNS::RR->new("

example.com.	                       3600    RRSIG   DNSKEY 5 2 3600 20380101000000 (
                                        20080225134340 40620 example.com.
                                        KXDsJ6gOFbGUA8cSwLIgnHQ2GwfpUJLWZK7/
                                        MwF7+G2B5Ds7SQG1UWv0QuyNtWB0ubSn2ipw
                                        4TclHDKjeYMFLD6I5Zuh4mW7n2QpPN79z57V
                                        C4Hf23lcWLRSL37jtX2qOPqWnFjy1AoGYzmy
                                        IksYcjPF5VPZyfQC0YprAQ35UKwAHfF9RMwi
                                        7vdE0GzON1FkVCWN7uxYjnZT1jxs3EeSnR4+
                                        6ckK9OBJVHYUnjmIgViq6IuPV08zrelvZHcC
                                        WNFcjKKNpf3yx5YhyQBJBM6Fofl8Dk4zexsp
                                        VVjGDLrDwg73dOGEe3E00DQ9zDc++PGVNRPm
                                        r34ojumh85Ua0YVatw== )

");



my    $binddataset=[$bindkey1, $bindkey2];

ok( $bindsig->verify($binddataset,$bindkey1),
    'RSA sig generated with bind verifies') || diag ($bindsig->vrfyerrstr);        




my $nsecrr=Net::DNS::RR->new("example.com   300     NSEC    itemA.with.caps.example.com. NS SOA TXT RRSIG NSEC DNSKEY
");

ok ( $nsecrr, 'NSEC RR created from string');		

my $nsecsig=Net::DNS::RR->new("

example.com.  300     RRSIG   NSEC 5 2 300 20380101000000 (
                                        20080225134340 6227 example.com.
                                        TyfSavDAslOFzfiAQv29/KjGQBSyptVIHAl/
                                        +BtV7YL7VBOBBxpYM0laQWfnvRPwqfqO0STD
                                        u3KpIH95/ZeIPA/20xqR9IqgQNx3NvMmNK2g
                                        R0qPK/tkKQpHsBGPgARXhQqUwT2HhhmwNOYb
                                        ZwvnbaarFVq3RWerJUAxWHm3OABqZ1RYr6rL
                                        JEIIwEuBs9zAmR0G03Ourg+vVzkIgOoiEcBy
                                        ketBJr7FfFsRAYJ0HWOupSw16lxoUkSrEZ/f
                                        NpSwOB7zdEuDeojcfK0JaanpWihA0hiiqq0D
                                        7RKqrnkoTrPVN4lP7bIr4q52jEBlFVIrbIzL
                                        UGtebocRBrvlmVB3+A== )



");


my @nsecdata=($nsecrr);

ok( $nsecsig->verify(\@nsecdata,$bindkey2), "RRSIG over NSEC verifies") || 
    diag ($nsecsig->vrfyerrstr);        
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





is ($dsakeyrr->keylength, 8, "DSA (KEY) Keysize ");
is ($rsakeyrr->keylength, 1024, "RSA (KEY) Keysize ");
is ($bindkey1->keylength, 2048, "RSA (DNSKEY) Keysize ");



