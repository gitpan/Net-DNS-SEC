#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 12-nsec++.t 296 2005-05-27 11:31:07Z olaf $
# 
use Net::DNS::RR::RRSIG;

use Test::More tests=>10;
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
is (unpack("H*",$rr->typebm()),$newbitmap,"typebm appropritatly changed after invoking typelist method");


$rr2->typebm(pack("H*",$newbitmap));
is ($rr2->typelist,$newtypelist,"typelist appropritatly changed after invoking typelist method");
