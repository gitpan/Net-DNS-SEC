#!/usr/bin/perl  -sw 
# Test script for loading parser and zonemodules
# $Id: 00-load.t 778 2008-12-30 17:19:35Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/<foo>

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.


use Test::More tests=>2;
use strict;

#use Data::Dumper;
BEGIN {use_ok('Net::DNS::SEC', 
      qw(key_difference
         verify_selfsig));


      }                                 # test 1

require_ok('Net::DNS::SEC');


diag("\nThese tests were ran with:\n");
diag("Net::DNS::VERSION:               ".
     $Net::DNS::VERSION);
diag("Net::DNS (SVN) Version           "
     .$Net::DNS::SVNVERSION);
diag("Net::DNS::SEC::VERSION:          ".
     $Net::DNS::SEC::VERSION);
diag("Net::DNS::SEC::SVNVERSION:          ".
     $Net::DNS::SEC::SVNVERSION);
diag("Net::DNS::RR::RRSIG::VERSION: ".
     $Net::DNS::RR::RRSIG::VERSION);
diag("Net::DNS::RR::DNSKEY::VERSION: ".
     $Net::DNS::RR::DNSKEY::VERSION);
diag("Net::DNS::RR::NSEC::VERSION: ".
     $Net::DNS::RR::NSEC::VERSION);
diag("Net::DNS::RR::NSEC3::VERSION: ".
     $Net::DNS::RR::NSEC3::VERSION);
diag("Net::DNS::RR::NSEC3PARAM::VERSION: ". 
     $Net::DNS::RR::NSEC3PARAM::VERSION);
diag("Net::DNS::RR::DS::VERSION: ".
     $Net::DNS::RR::DS::VERSION);
diag("Net::DNS::RR::DLV::VERSION: ".
     $Net::DNS::RR::DLV::VERSION);
diag("Crypt::OpenSSL::DSA::VERSION: ".
     $Crypt::OpenSSL::DSA::VERSION);
diag("Crypt::OpenSSL::RSA::VERSION: ".
     $Crypt::OpenSSL::RSA::VERSION);
diag("Crypt::OpenSSL::Bignum::VERSION: ".
     $Crypt::OpenSSL::Bignum::VERSION);
diag("Net::DNS::SEC::Private::VERSION: ".
     $Net::DNS::SEC::Private::VERSION);
diag("File::Basename::VERSION: ".
     $File::Basename::VERSION);
diag("MIME::Base64::VERSION: ".
     $MIME::Base64::VERSION);
diag("MIME::Base32::VERSION: ".
     $MIME::Base32::VERSION);
diag("Math::BigInt::VERSION: ".
     $Math::BigInt::VERSION);
diag("Time::Local::VERSION: ".
     $Time::Local::VERSION);
diag("Digest::SHA::VERSION: ".
     $Digest::SHA::VERSION);




