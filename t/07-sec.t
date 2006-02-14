# Test script for dnssec functionalty   -*-perl-*-
# $Id: 07-sec.t 556 2006-02-14 09:51:57Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/07-sec.t

use Test::More tests=>23;
use strict;
use MIME::Base64;


BEGIN {
  use_ok('Net::DNS::SEC::Private'); 
}                                 # test 1

diag ("Testing the algorithm method");

is (Net::DNS::SEC->algorithm("DSA"),3,"Class method parses DSA");
is (Net::DNS::SEC->algorithm("DsA"),3,"Class method parses DsA");
is (Net::DNS::SEC->algorithm("RSASHA1"),5,"Class method parses RSASHA1");
is (Net::DNS::SEC->algorithm("RSAMD5"),1,"Class method parses RSAMD5");
diag ("Do not worry about the warning");
is (Net::DNS::SEC->algorithm("CRYPTSAM"),undef,"Class method returns undef with CRYPTSAM");


ok (my $keyrr=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 1 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");



is( $keyrr->algorithm,1,"DNSKEY with numeric specification of the RR read from string");

ok (my $keyrr2=Net::DNS::RR->new("test.tld. IN DNSKEY 256 3 RSAMD5 AQPoBLAXetIEWcEFDs+Z1Ymc2RPZeRtk/kF7bxLJOiGye5PVHDs6Vs1U 2JP7hLTglRLSK1Vu+C1iYNkYxTed9k/56vbS4lGj+a7qFKQlbcxfkRLy j8ac5JPXNIIfX5oDVjoCWF8t5sL7KxUp+0ticRyjqgc2Khg6ZgejNivl 3S0v+w=="),"Key succesfully created");


is( $keyrr2->algorithm,1,"DNSKEY with string specification of the RR read from string");


is ($keyrr2->algorithm("mnemonic"),"RSAMD5","mnemonic works as argument");

use Data::Dumper;


# This keyblob represents t/Kexample.com.+005+34247.private;
# using 'openssl rsa -modulus', 'openssl rsa -text' I double
# checked if the values reported by openssl and those in the file
# are consistent.

my $keyblob="-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCqyylc732/AE42mlUE3g44JS3O4tdvUwOK3lwpQ/xOJX6gFLEg
/SRK36FXnXqbJzkqCkwVrCgbA2SM63axme57vbbnppljuiCKf6rxZE2602YhOLPd
sw+1nRRyHZ8fPv761H8bPS9Zcx3IQyE33l1B+tPN9MtQus6fcsQy2tIwuwIBAwKB
gHHcxj30/n9ViXm8OK3pXtAYyTSXOko3V7HpksYtUt7DqcANy2tTbYc/wOUTpxIa
JhwG3WPIGrys7bNHpHZmnvwSTuZCYv7G6X9fG29P4HMMp4DvMlLRYcwoqcxax8DN
4XG/jBN/tfTkgUzO9sMtP6SDGsegTRER8WsYH3Ysg0L7AkEA1GAZ1v3tA96l2os1
enQEtINZ/Q2IHsd7Rr32qaTAS9qtTT5DQJKFvTA36+6+UiZ/0OxUaH2VECpuMHvh
3vz8xQJBAM3gdGwG+IvjpZZ2lPIJCYvnhdTa2Vo1iBlXyOvOvb5SIufuur0L5F8r
nSDAVMhXS2U/ThvaIg+6EJ4ZH7kQT38CQQCNlWaPU/NX6cPnB3j8TVh4V5FTXlq/
L6eEfqRxGIAykcjeKYIrDFkoys/ynymMGaqLSDhFqQ4KxvQgUpaUqKiDAkEAiUBN
nVn7B+0ZDvm4oVtbsppZOJHmPCOwEOUwnTR+fuFsmp8nKLKYP3JowIA4hY+HmNTe
vTwWtSa1vrtqe2A0/wJAOGDWYhImmtzR/wYJyBliYPnn5fbMS/B9eL+PWC0+whBQ
A5WkPqeImlJKkr7oWZE+VmuxicpW2VPVacMQYsV3dg==
-----END RSA PRIVATE KEY-----
";


my $privkeyfilename="t/Kexample.com.+005+34247.private";
my $pubkeyfilename="t/Kexample.com.+005+34247.key";
my $rsakey=Net::DNS::SEC::Private->new($privkeyfilename);
my $privkey;
my $pubkey;

my $rsakeyfromder=Net::DNS::SEC::Private->new_rsa_priv($rsakey->dump_rsa_private_der);
is ($rsakey->dump_rsa_private_der,$rsakeyfromder->dump_rsa_private_der, "Consistent DER parsing");


is ($rsakey->dump_rsa_private_der,$keyblob, "Consistent DER with keyblob");







#encode_base64($modulus) ."\n";


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





$privkeyfilename="t/Kexample.com.+001+28551.private";
$pubkeyfilename="t/Kexample.com.+001+28551.key";
$rsakey=Net::DNS::SEC::Private->new($privkeyfilename);

$rsakeyfromder=Net::DNS::SEC::Private->new_rsa_priv($rsakey->dump_rsa_private_der);
is ($rsakey->dump_rsa_private_der,$rsakeyfromder->dump_rsa_private_der, "Consistent DER parsing");
is($rsakey->dump_rsa_keytag(255,1),28551,"Consistent RSAMD5 keytag");
