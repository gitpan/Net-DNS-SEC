# $Id: 16-dlv.t 778 2008-12-30 17:19:35Z olaf $                 -*-perl-*-
#
#
#  These are test that relate to DLV RRs.
# Mainly used during implementation of the SHA256 algorithm


use Test::More; 
use strict;

use Net::DNS;

plan tests=>2;


my $dnskeyrr=Net::DNS::RR->new('dskey.example.com. 86400 IN DNSKEY 256 3 5 (
                                                AQOeiiR0GOMYkDshWoSKz9Xz
                                                fwJr1AYtsmx3TGkJaNXVbfi/
                                                2pHm822aJ5iI9BMzNXxeYCmZ
                                                DRD99WYwYqUSdjMmmAphXdvx
                                                egXd/M5+X7OrzKBaMbCVdFLU
                                                Uh6DhweJBjEVv5f2wwjM9Xzc
                                                nOf+EPbtG9DMBmADjFDc2w/r
                                                ljwvFw==
                                                ) ;  key id = 60485');

my $dsrr=Net::DNS::RR->new('dskey.example.com. 86400 IN DLV 60485 5 2 ( 
                                                D4B7D520E7BB5F0F67674A0C
                                                CEB1E3E0614B93C4F9E99B83
                                                83F6A1E4469DA50A )');


$dsrr->print;
ok($dsrr->verify($dnskeyrr),"Validated the SHA256 DLV");


my $newdsrr=create Net::DNS::RR::DLV($dnskeyrr,
	(
	 digtype => "SHA256"
	)
    );
ok($newdsrr->verify($dnskeyrr),"Validated the second SHA256 DLV");


