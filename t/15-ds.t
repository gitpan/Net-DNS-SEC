# $Id: 15-ds.t 813 2009-11-27 09:10:10Z olaf $                 -*-perl-*-
#
#
#  These are test that relate to DS RRs.
# Mainly used during implementation of the SHA256 algorithm


use Test::More; 
use strict;

use Net::DNS;

plan tests=>3;


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

my $dsrr=Net::DNS::RR->new('dskey.example.com. 86400 IN DS 60485 5 2 ( 
                                                D4B7D520E7BB5F0F67674A0C
                                                CEB1E3E0614B93C4F9E99B83
                                                83F6A1E4469DA50A )');


$dsrr->print;
ok($dsrr->verify($dnskeyrr),"Validated the SHA256 DS");


my $newdsrr=create Net::DNS::RR::DS($dnskeyrr,
	(
	 digtype => "SHA256"
	)
    );
ok($newdsrr->verify($dnskeyrr),"Validated the second SHA256 DS");


my $ds1 = Net::DNS::RR->new(
'algorithm' => 3,
'class' => 'IN',
'digest' => '1234567890ABCDEF',
'digtype' => 5,
'keytag' => 123,
'name' => 'test1dom1.se',
'ttl' => 43200,
'type' => 'DS',
'digestbin' => ''
);
#error only occurs when next line is commented


my $ds2 = Net::DNS::RR->new(
'algorithm' => 3,
'class' => 'IN',
'digest' => '1234567890ABCDEF',
'digtype' => 5,
'keytag' => 123,
'name' => 'test1dom1.se',
'ttl' => 43200,
'type' => 'DS',
);


is ($ds1->string,$ds2->string,"Digestbin calculation correct");


