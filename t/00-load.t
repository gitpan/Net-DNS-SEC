#!/usr/bin/perl  -sw 
# Test script for loading parser and zonemodules
# $Id: 00-load.t 1171 2014-02-26 08:56:52Z willem $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/<foo>

# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'


use strict;

BEGIN {
	use Test::More tests => 2;

	use_ok( 'Net::DNS::SEC', qw(key_difference) );		# test 1

	require_ok('Net::DNS::SEC');				# test 2
}


diag("\nThese tests were run with:\n");
diag("	Net::DNS::SEC			$Net::DNS::SEC::VERSION");
diag("	Net::DNS::SEC	(SVN)		$Net::DNS::SEC::SVNVERSION");
diag("	Net::DNS			$Net::DNS::VERSION");
diag("	Net::DNS	(SVN)		$Net::DNS::SVNVERSION");

my @module = qw(
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
	Crypt::OpenSSL::DSA
	Crypt::OpenSSL::RSA
	Crypt::OpenSSL::Bignum
	Digest::SHA
	File::Basename
	Math::BigInt
	MIME::Base64
	MIME::Base32
	Time::Local
	);

foreach my $module (@module) {
	eval("require $module");
	diag sprintf "\t%-30s\t%s", $module, ${module}->VERSION;
}

