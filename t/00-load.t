#!/usr/bin/perl  -sw 
# Test script for loading parser and zonemodules
# $Id: 00-load.t 1289 2015-01-05 10:08:59Z willem $
# 
# Called in a fashion similar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/<foo>

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'


use strict;

BEGIN {
	use Test::More tests => 2;

	use_ok('Net::DNS::SEC');				# test 1

	require_ok('Net::DNS::SEC');				# test 2
}


my @module = qw(
	Net::DNS::SEC
	Net::DNS
	Net::DNS::RR::CDNSKEY
	Net::DNS::RR::CDS
	Net::DNS::RR::DNSKEY
	Net::DNS::RR::DS
	Net::DNS::RR::DLV
	Net::DNS::RR::KEY
	Net::DNS::RR::NSEC
	Net::DNS::RR::NSEC3
	Net::DNS::RR::NSEC3PARAM
	Net::DNS::RR::RRSIG
	Net::DNS::RR::SIG
	Net::DNS::SEC::Private
	Crypt::OpenSSL::Bignum
	Crypt::OpenSSL::DSA
	Crypt::OpenSSL::EC
	Crypt::OpenSSL::ECDSA
	Crypt::OpenSSL::RSA
	Digest::BubbleBabble
	Digest::GOST
	Digest::SHA
	File::Spec
	MIME::Base64
	MIME::Base32
	Time::Local
	);


diag("\nThese tests were run with:\n");
foreach my $module (@module) {
	my $loaded = eval("require $module");
	diag sprintf "\t%-25s\t%s", $module, $loaded ? ${module}->VERSION || '?' : '';
}

