#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 12-nsec++.t 1112 2013-09-20 08:57:49Z willem $
# 



use Net::DNS::SEC;
use Test::More tests=>17;
use Data::Dumper;
use Net::DNS::RR::NSEC3 qw( name2hash );


use strict;

BEGIN {use_ok('Net::DNS'); }                                 # test 1

# Example draft-ietf-dnsext-nsec-rdata-01
my $typebmhex="
00 06 40 01 00 00 00 03
04 1b 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 20";

$typebmhex=~ s/\s//g;
my $typebm=pack("H*",$typebmhex);


is (join(" ",Net::DNS::RR::NSEC::_typebm2typearray($typebm)),"A MX NSEC RRSIG TYPE1234","typebmhex function returns expected");

my @typearray=qw(A MX RRSIG NSEC TYPE1234);
$typebm=Net::DNS::RR::NSEC::_typearray2typebm(@typearray);


ok(my $rr=Net::DNS::RR->new("alfa.example.com 86400 IN NSEC host.example.com A MX TYPE1234 NSEC RRSIG "), "NSEC generated");

is( $rr->typelist,"A MX NSEC RRSIG TYPE1234","Typelist Correctly generated");
is ($rr->nxtdname,"host.example.com", "nxtdname correctly parsed");

is (unpack("H*",$rr->typebm),$typebmhex,"Typebitmap generated correctly");


# Testing the construction of a new object using hashes and using typelist 
# instead of bitmaps.


my $rr2=Net::DNS::RR->new(name=> "alfa.example.com",
		      ttl=> 86400,
		      type=>"NSEC",
		      nxtdname=>"host.example.com",
	      typelist=>" A MX TYPE1234 NSEC RRSIG ",
		      );





is( unpack("H*",$rr2->typebm()), unpack("H*",$rr->typebm()), "typebitmaps equal");

is( join(" ", sort split(' ',$rr2->typelist())),  join(" ", sort split(' ',$rr->typelist())), "typelists equal");



my $newbitmap="00060008000000031606000000000002";
my $newtypelist="NSEC PTR RRSIG TYPE5678";
$rr->typelist($newtypelist);
is (unpack("H*",$rr->typebm()),$newbitmap,"typebm changed appropriately after invoking typelist method");


$rr2->typebm(pack("H*",$newbitmap));
is ($rr2->typelist,$newtypelist,"typelist changed appropriately after invoking typelist method");


########################


my $foo={};;



bless($foo,"Net::DNS::RR::NSEC3");
$foo->salt("aabbccdd");

# H(example) = 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom

is ("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",lc Net::DNS::RR::NSEC3::name2hash(1,"example.",12,$foo->saltbin),"name2hash over example");


# H(x.w.example) = b4um86eghhds6nea196smvmlo4ors995
is ("b4um86eghhds6nea196smvmlo4ors995",lc Net::DNS::RR::NSEC3::name2hash(1,"x.w.example.",12,$foo->saltbin),"name2hash over example");

# H(c.x.w.example) = 0va5bpr2ou0vk0lbqeeljri88laipsfh

is ("0va5bpr2ou0vk0lbqeeljri88laipsfh",lc Net::DNS::RR::NSEC3::name2hash(1,"c.x.w.example.",12,$foo->saltbin),"name2hash over example");


# H(*.x.w.example) = 92pqneegtaue7pjatc3l3qnk738c6v5m
is ("92pqneegtaue7pjatc3l3qnk738c6v5m",lc Net::DNS::RR::NSEC3::name2hash(1,"*.x.w.example.",12,$foo->saltbin),"name2hash over example");



my $nsec3param = eval{ Net::DNS::RR->new("alfa.example.com 86400 NSEC3PARAM 2 0 12 aabbccdd") };
print $@ if $@;
ok ($nsec3param, "NSEC3PARAM created");

$nsec3param = eval{ Net::DNS::RR->new("alfa.example.com 86400 NSEC3PARAM 2 0 12 aabbccfs") };
print $@ if $@;
ok (!$nsec3param, "NSEC3PARAM not created with corrupt hex data");



my $hashalg=Net::DNS::SEC->digtype("SHA1");
my   $salt=pack("H*","aabbccdd");
my $iterations=12;
my    $name="*.x.w.example";

my  $hashedname= name2hash($hashalg,$name,$iterations,$salt);
is( $hashedname,"92pqneegtaue7pjatc3l3qnk738c6v5m","name2hash exports and works");
