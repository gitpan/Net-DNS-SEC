# Test script for dnssec functionalty
# $Id: 07-sec.t,v 1.1 2003/09/24 13:38:08 olaf Exp $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/07-sec.t

use Test::More tests=>11;
use strict;


BEGIN {
  use_ok('Net::DNS::SEC'); 
}                                 # test 1

diag ("Testing the algorithm method");

is (Net::DNS::SEC->algorithm("DSA"),3,"Class method parses DSA");
is (Net::DNS::SEC->algorithm("DsA"),3,"Class method parses DsA");
is (Net::DNS::SEC->algorithm("RSA/SHA1"),5,"Class method parses RSA/SHA1");
is (Net::DNS::SEC->algorithm("RSA/MD5"),1,"Class method parses RSA/MD5");
diag ("Do not worry about the warning");
is (Net::DNS::SEC->algorithm("CRYPTSAM"),undef,"Class method returns undef with CRYPTSAM");


ok (my $keyrr=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");

is( $keyrr->algorithm,1,"KEY with numeric specification of the RR read from string");

ok (my $keyrr2=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 RSA/MD5 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");


is( $keyrr2->algorithm,1,"KEY with string specification of the RR read from string");


is ($keyrr2->algorithm("mnemonic"),"RSA/MD5","mnemonic works as argument");
