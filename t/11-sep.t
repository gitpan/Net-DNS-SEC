#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 11-sep.t 813 2009-11-27 09:10:10Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/10-typeroll.t


use Test::More tests=>6;
use strict;

BEGIN {use_ok('Net::DNS'); }                                 # test 1


ok (my $key=Net::DNS::RR->new("test.foo       3600         IN DNSKEY  256 3 RSASHA1  (
                              AQPDgM2XU2rluutXFw6IJjDRSGHehcc1ZtMoG5RR/
                              jXJD1bZNFgqsKlJkVfj9wzrzAnBg7ZQSHwxYIGDm
                              ocdBtW3 )"),"Key created");


my $keytag=$key->keytag;

$key->set_sep;
ok ($key->is_sep,"Sep bit set");
ok ($keytag != $key->keytag, "keytag modified after toggle");
$key->clear_sep;

ok (!$key->is_sep,"Sep bit unset");
ok ($keytag == $key->keytag, "keytag modified back to original after toggle");
