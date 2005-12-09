#!/usr/bin/perl  -sw                         -*-perl-*-


use Test::More tests=>5;
use strict;


BEGIN {
  use_ok('Net::DNS'); 
}                                 # test 1



my $RR=Net::DNS::RR->new("example.com   IN	DS	
                             42495  RSASHA1  1  
                             0ffbeba0831b10b
                             8b83440dab81a2148576da
                             9f6");


my $string=$RR->string;
$string=~ s/\s+/ /g;
is($string, 'example.com. 0 IN DS 42495 5 1 0ffbeba0831b10b8b83440dab81a2148576da9f6 ; xefoz-rupop-babuc-rugor-mavef-gybot-puvoc-pumig-mahek-tepaz-kixox', "Correct parsing of DS RR RSASHA1 MNEMONIC");


undef $RR;
$RR=Net::DNS::RR->new("example.com   IN	DS	
                             42495  RSASHA1  SHA1  
                             0ffbeba0831b10b
                             8b83440dab81a2148576da
                             9f6");



$string=$RR->string;
$string=~ s/\s+/ /g;
is($string, 'example.com. 0 IN DS 42495 5 1 0ffbeba0831b10b8b83440dab81a2148576da9f6 ; xefoz-rupop-babuc-rugor-mavef-gybot-puvoc-pumig-mahek-tepaz-kixox', "Correct parsing of DS RR (SHA1 MNEMONIC)");

diag("Ignore the two error messages");


undef $RR;
$RR=Net::DNS::RR->new("example.com   IN	DS	
                             42495  RSASHA1  FOOO  
                             0ffbeba0831b10b
                             8b83440dab81a2148576da
                             9f6");


ok(! defined($RR),"string not parsed (digest mnemonic FOO)");
undef $RR;
$RR=Net::DNS::RR->new("example.com   IN	DS	
                             42495  FOOO   1
                             0ffbeba0831b10b
                             8b83440dab81a2148576da
                             9f6");

ok(! defined($RR),"string not parsed (algorithm mnemonic FOO)");
