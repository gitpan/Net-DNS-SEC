#!/usr/bin/perl -w 
# Just a little helper program to create the UUencoded packet data in 
# t/10-keyset.
#
# There is no real use for it except that you may look at the code.


use strict;
use Net::DNS::Resolver;

my $res = Net::DNS::Resolver->new;
$res->dnssec(1);
$res->nameservers('10.0.53.203');
my $packet = $res->query ("sub.tld", "KEY", "IN");
$packet->print;
my $Uencoded=unpack("H*",$packet->data);
print $Uencoded;
