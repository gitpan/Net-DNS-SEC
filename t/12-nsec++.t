#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 12-nsec++.t,v 1.2 2003/12/10 08:50:15 olaf Exp $
# 
use Net::DNS::RR::RRSIG;

use Test::More tests=>6;
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


is (join(" ",Net::DNS::RR::NSEC::_typebm2typestr($typebm)),"A MX NSEC RRSIG TYPE1234","typebmhex function returns expected");

my @typearray=split(/\s+/,"A MX RRSIG NSEC TYPE1234");
$typebm=Net::DNS::RR::NSEC::_typestr2typebm(@typearray);


ok(my $rr=Net::DNS::RR->new("alfa.example.com 86400 IN NSEC host.example.com A MX TYPE1234 NSEC RRSIG "), "NSEC generated");

is( $rr->typelist,"A MX NSEC RRSIG TYPE1234","Typelist Correctly generated");
is ($rr->nxtdname,"host.example.com", "nxtdname correctly parsed");

is (unpack("H*",$rr->typebm),$typebmhex,"Typebitmap generated correctly");
