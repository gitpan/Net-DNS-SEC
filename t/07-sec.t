# Test script for dnssec functionalty
# $Id: 07-sec.t,v 1.4 2004/06/11 16:14:35 olaf Exp $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/07-sec.t

use Test::More tests=>19;
use strict;


BEGIN {
  use_ok('Net::DNS::SEC::Private'); 
}                                 # test 1

diag ("Testing the algorithm method");

is (Net::DNS::SEC->algorithm("DSA"),3,"Class method parses DSA");
is (Net::DNS::SEC->algorithm("DsA"),3,"Class method parses DsA");
is (Net::DNS::SEC->algorithm("RSA/SHA1"),5,"Class method parses RSA/SHA1");
is (Net::DNS::SEC->algorithm("RSA/MD5"),1,"Class method parses RSA/MD5");
diag ("Do not worry about the warning");
is (Net::DNS::SEC->algorithm("CRYPTSAM"),undef,"Class method returns undef with CRYPTSAM");


ok (my $keyrr=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");



is( $keyrr->algorithm,1,"DNSKEY with numeric specification of the RR read from string");

ok (my $keyrr2=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 RSA/MD5 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");


is( $keyrr2->algorithm,1,"DNSKEY with string specification of the RR read from string");


is ($keyrr2->algorithm("mnemonic"),"RSA/MD5","mnemonic works as argument");

my $keyblob="
-----BEGIN RSA PRIVATE KEY-----
MIIBOAIBAAJBALdkuixDzXZFSqc/c9lknrbnVrw2zQ0l4AkKJFxRvQ0LYu6GObrK
DeWqk6xnAwnrStOvEDsY13dczPXdj+6CVbECAwEAAQJADoMYAFy1K4C8MZPh1PgT
XyHbSTWE8F9o5Q46ZlvJe/iiYfw24cQSdx7BNR7I+ANmNiaEu3/jsN0VivM7mNLr
yQIhAN/pPIRxk4q3CQ0FYQhFpe9hRk51DEFTigIA6ueLmGbvAiEA0az/Bwh/2v2a
GvJzkADFylcGlA/d1GZTzzNOJqfmDV8CIBDJGllPbmEawZnxSknldsAQScX97lJD
Yfgue22qQF2PAh9hdwkVO94y7a+01v7g8Xr/k3R7XuS+1tIefrrVPTazAiAEE3PW
xS7KGJg6DinLkyxxnRvoujJsUdBL6B+o196zcA==
-----END RSA PRIVATE KEY-----
";


use Data::Dumper;

my $rsakey=Net::DNS::SEC::Private->new_rsa_priv($keyblob);



my $privkeyfilename="t/Kexample.com.+005+34247.private";
my $pubkeyfilename="t/Kexample.com.+005+34247.key";
my $rsakey=Net::DNS::SEC::Private->new($privkeyfilename);
my $privkey;
my $pubkey;

open(PRIVKEYFILE,"<$privkeyfilename" )|| die "Could not open testfile $privkeyfilename\n";

while (<PRIVKEYFILE>){
    $privkey.=$_;
}

open(PUBKEYFILE,"<$pubkeyfilename" )|| die "Could not open testfile $pubkeyfilename\n";

while (<PUBKEYFILE>){
    $pubkey.=$_;
}

my $pubkeyrr=Net::DNS::RR->new($pubkey);


my $dumpkey=$rsakey->dump_rsa_priv;
is( $dumpkey,$privkey,"Read and dumped private keys equal");
my $key_rdata=$rsakey->dump_rsa_pub;
my $key_rr_rdata=$pubkeyrr->key;
is ($key_rr_rdata,$key_rdata,"Read and dumped public keys equal");

is($rsakey->dump_rsa_keytag(256),34247,"Calculated proper keytag");


# more consistency checking... Dump priv key into der format.. read it and 
# check again.
my $der=$rsakey->dump_rsa_private_der;
my $rsakey2=Net::DNS::SEC::Private->new_rsa_priv($der);
my $dumpkey2=$rsakey2->dump_rsa_priv;
is( $dumpkey2,$privkey,"Read and dumped private keys equal");
my $key_rdata2=$rsakey2->dump_rsa_pub;
is ($key_rr_rdata,$key_rdata2,"Read and dumped public keys equal");




my $newkey=Net::DNS::SEC::Private->generate_rsa("example.com",257,1024);
my $tstpubkeyrr= Net::DNS::RR->new ($newkey->signame."  IN DNSKEY 257 3 5 ".
				    $newkey->dump_rsa_pub());
is($tstpubkeyrr->keytag,$newkey->dump_rsa_keytag(),"Consistent keytag calculation");

my $sigrr= create Net::DNS::RR::RRSIG([$tstpubkeyrr],$newkey);
is ($sigrr->keytag,$tstpubkeyrr->keytag,"Consisted keytag in the created signature");;

ok($sigrr->verify([$tstpubkeyrr],$tstpubkeyrr), "Self verification consistent.");
