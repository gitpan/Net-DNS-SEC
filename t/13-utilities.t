#!/usr/bin/perl  -sw 
# Test script for dnssec functionalty
# $Id: 13-utilities.t 222 2005-03-04 09:03:31Z olaf $
# 
# Called in a fashion simmilar to:
# /usr/bin/perl -Iblib/arch -Iblib/lib -I/usr/lib/perl5/5.6.1/i386-freebsd \
# -I/usr/lib/perl5/5.6.1 -e 'use Test::Harness qw(&runtests $verbose); \
# $verbose=0; runtests @ARGV;' t/13-utilities


use Test::More tests=>6;
use strict;

use Net::DNS::Keyset;
use Net::DNS::SEC qw( key_difference);



my $rr; 
my @keyrr;
my @keyrr2;
my @sigrr;



# Note that the order on pushing the RRsigs is important for
# succesfully testing.

# All signatures have expiration date in 2030... this test should work for a while

$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQOxFlzX8vShSG3JG2J/fngkgy64RoWr8ovG
					e7MuvPJqOMHTLM5V8+TJIahSoyUd990ictNv
					hDegUqLtZ8k5oQq44viFCU/H1apdEaJnLnXs
					cVo+08ATlEb90MYznK9K0pm2ixbyspzRrrXp
					nPi9vo9iU2xqWqw/Efha4vfi6QVs4w==
					) ");

push(@keyrr,$rr);
push(@keyrr2,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO4jhl6ilWV2mYjwWl7kcxrYyQsnnbV7pxX
					m48p+SgAr+R5SKyihkjg86IjZBQHFJKZ8RsZ
					dhclH2dikM+53uUEhrqVGhsqF8FsNi4nE9aM
					ISiX9Zs61pTYGYboYDvgpD1WwFbD4YVVlfk7
					rCDP/zOE7H/AhkOenK2w7oiO0Jehcw==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);
my $poppedkey=Net::DNS::RR->new($rr->string);


$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO5fWabr7bNxDXT8YrIeclI9nvYYdKni3ef
					gJfU749O3QVX9MON6WK0ed00odQF4cLeN3vP
					SdhasLDI3Z3TzyAPBQS926oodxe78K9zwtPT
					1kzJxvunOdJr6+6a7/+B6rF/cwfWTW50I0+q
					FykldldB44a1uS34u3HgZRQXDmAesw==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	DNSKEY	256 3 5 (
					AQO6uGWsox2oH36zusGA0+w3uxkZMdByanSC
					jiaRHtkOA+gIxT8jmFvohxQBpVfYD+xG2pt+
					qUWauWPFPjsIUBoFqHNpqr2/B4CTiZm/rSay
					HDghZBIMceMa6t4NpaOep79QmiE6oGq6yWRB
					swBkPZx9uZE7BqG+WLKEp136iwWyyQ==
					) ");
push(@keyrr,$rr);
push(@keyrr2,$rr);

$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 11354 example.com.
					GTqyJTRbKJ0LuWbAnNni1M4JZ1pn+nXY1Zuz
					Z0Kvt6OMTYCAFMFt0Wv9bncYkUuUSMGM7yGG
					9Z7g7tcdb4TKCqQPYo4gr3Qj/xgC4LESoQs0
					yAsJtLUiDfO6e4aWHmanpMGyGixYzHriS1pt
					SRzirL1fTgV+kdNs5zBatUHRnQc=) ");

push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 28109 example.com.
					WemQqA+uaeKqCy6sEVBU3LDORG3f+Zmix6qK
					9j1WL83UMWdd6sxNh0QJ0YL54lh9NBx+Viz7
					gajO+IM4MmayxKY4QVjp+6mHeE5zBVHMpTTu
					r5T0reNtTsa8sHr15fsI49yn5KOvuq+DKG1C
					gI6siM5RdFpDsS3Rmf8fiK1PyTs= )");
push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 33695 example.com.
					M3yVwTOMw+jAKYY5c6oS4DH7OjOdfMOevpIe
					zdKqWXkehoDg9YOwz8ai17AmfgkjZnsoNu0W
					NMIcaVubR3n02bkVhJb7dEd8bhbegF8T1xkL
					7rf9EQrPmM5GhHmVC90BGrcEhe//94hdXSVU
					CRBi6KPFWSZDldd1go133bk/b/o= )");
push(@sigrr,$rr);
$rr=Net::DNS::RR->new("example.com	100 IN	RRSIG	DNSKEY 5 2 100 20300101000000 (
					20040601105519 39800 example.com.
					Mmhn2Ql6ExmyHvZFWgt+CBRw5No8yM0rdH1b
					eU4is5gRbd3I0j5z6PdtpYjAkWiZNdYsRT0o
					P7TQIsADfB0FLIFojoREg8kp+OmbpRTsLTgO
					QYC95u5WodYGz03O0EbnQ7k4gkje6385G40D
					JVl0xVfujHBMbB+keiSphD3mG4I= )");


push(@sigrr,$rr);
#
# Test key_difference function from Net::DNS::SEC
#

# @keyrr and @keyrr2 contain exactly the same data, we'll now add two different
# keys to @keyrr2 and to an array to compare the results agains.

my @result;
my @testresult;

$rr=Net::DNS::RR->new("example.com. IN DNSKEY 256 3 5 AQOxZqVCFGc1pNh8TVnxPwcEauBXgxKFOc9stE/aKCQP/2vFE7N2agu+ /LlQlTmKFWLaGfJnVazLDEFi3Fp4PK1Z");
push(@keyrr2,$rr);
push(@testresult,$rr);

$rr=Net::DNS::RR->new("example.com. IN DNSKEY 256 3 5 AQOURUjSxNm1X5wIfSzUHWl8kOpVwCFVaCpn/qrIrdOMTetNA1M3Ph4g xaH+JNxYETFw+cH9ZZqhawd95mON1HJv");
push(@keyrr2,$rr);
push(@testresult,$rr);

ok(!key_difference(\@keyrr2,\@keyrr,\@result), "key_difference returns 0 as return code");
#test 1

ok( eq_array(\@result,\@testresult),"key_difference fills the return array with correct values");
# test 2


my $dummy=Net::DNS::RR->new("example.com IN A 10.0.0.1");
push(@keyrr2,$dummy);
is(key_difference(\@keyrr2,\@keyrr,\@result),"First array contains something different than a Net::DNS::RR::DNSKEY objects (Net::DNS::RR::A)", "key_difference returns proper error with non DNSKEY objects in 1st array");
# test 3


is(key_difference(\@keyrr,\@keyrr2,\@result),"Second array contains something different than a Net::DNS::RR::DNSKEY objects (Net::DNS::RR::A)", "key_difference returns proper error with non DNSKEY objects in 2nd array");
#test 4
# Remove that dummy again.
pop (@keyrr2);

@result=();
ok( !key_difference(\@keyrr,\@keyrr2,\@result), "key_difference returns 0 as return code"); # test 5

is (@result,0,"key_difference returned empty array when 1st array is subset of 2nd");  # test 6
