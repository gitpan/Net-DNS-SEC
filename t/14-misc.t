# $Id$                 -*-perl-*-
#
#
#  This is a hodgepodge of tests that are used to reproduce bugs found in
#  previous releases.


use Test::More; 
use strict;

use Net::DNS;

plan tests=>4;
my $nsec1=Net::DNS::RR->new(
    "example.com.			300	NSEC	itemA.with.caps.example.com. NS SOA TXT RRSIG NSEC DNSKEY");


my $nsec2=Net::DNS::RR->new(
    "itemA.with.caps.example.com. 			300	NSEC	itemb.without.caps.example.com. TXT RRSIG NSEC");




my $sig_nsec1=Net::DNS::RR->new('example.com.   300	RRSIG	NSEC 5 2 300 20301204005203 (
					20051104005258 6227 example.com.
					gXP6L0gw0WRfjVRn1I4KnQf5Eg0qsMScYjBW
					A8lWQHUx1JOIikLbsD+NA8sl9sIkHwxTeTdJ
					2CycDZdHoy/QI3oRG1DVqiXIBD0PhKcdxO6e
					j65l8BokA0imnxwccufJjLKBhGO9argi+R72
					TNDxDU5OVKjglSosSOtjcwI5T+bJfgM62MsU
					1BWByNA2suCWxANhL9r+Tl9UZttdZ+cH8Xfw
					Fng2MSNaZw+snCCeE8sFqycY0DcnTub/O9bK
					NQErcKN9pK/BHGfQp4b8hHaeWF3nQbEVdA/y
					ISrgNXaJ4hQ0PhdxYbE5nO4KUPcDalPj1fW4
					VxHnQg69lIz3QcgO0Q== )
			');


my $sig_nsec2=Net::DNS::RR->new("itemA.with.caps.example.com.	300	RRSIG	NSEC 5 5 300 20301204005203 (
					20051104005258 6227 example.com.
					zb11rwmxrgbfzIVV0V/wlJdAvmy1qZueQ1F7
					UTtImaxbxZCrTeGmWyJE3iZAMQp2m+ybTrU0
					wIXCPCd8kG9bBQUJJTO02tnJRDsiVOxJjVkS
					XbLOAZl9ycBT/A+963hAw7MS0oH3FxreyXHw
					PXrk8VHEOU7kZFNOGHsQZutlPWbucbMX/RrP
					8Hso3h1aZ6SphA3K4a4UMVnlpezb2T+pWqV8
					nM5Sj0x1UGIZFLMpWpF0o/dPMsdzaW4vizTk
					DySeu0BXDcWO2eIPdKTd80yHTITh8JrvJB1s
					pupGkoAN2VgNKTUZ3wE5oeAdUP7Sn7TPTLnk
					a8rvoxcqm6hqdrYsuQ== )");



my $dnskey=Net::DNS::RR->new('example.com 			3600	DNSKEY	256 3 5 (
					AQPaoHW/nC0fj9HuCW3hACSGiP0AkPS3dQFX
					DlEUjv1orbtx06TMmVKGK5K564OSd6UCf4ZQ
					Eu2CMPSAUFGHEZuANKYGwZh0k/HeoVNeom1L
					3Nt4tVLiGMzrPQskzeK8sr1NKgqFmckQllMW
					d0ob8Ud6nqeQLHvXQgv1iHX3dpBIPLYbRCzu
					eqC5k09APl25PgJjjreyRXrxodvoiiaLHpdL
					5NtM2S9eok2zmuRpYQSF1LTNfWwY9CkgL017
					Z/Zv00SbcoTM/eTXPqijGtUhh6UX1gX89ybe
					yjtfcGbmTcB+I79NykZWoddO8zyzBXzzfFwt
					sAuryjQ/HFa5r4mrbhkJ
					) ; key id = 6227
');


my $sig_nsec1_ldns=Net::DNS::RR->new("
example.com.    300     IN      RRSIG   NSEC RSASHA1 2 300 20380119031407 200703
09133715 6227 example.com. aXhXGPs5tiGFM4NFmgtsj7jW4p6A/hnY2JOwfD/gK1bFTIF/wHTRh
na7t1L3auWileX1OymoivDw+HzoRnpL+IStqv4/7P0mMHGwwuyjhpMry8FMf1p3La8IzMV8pmAYsEENb
3izYio3Hjrvvnw2uv2IWOgf1zPmndlmV0B5gOuSJEkyDFP8Z6Zshaou+oGjmDGwMNt0e6IW7yg2r92+9
NNJiGk3EcRnC0uzFVs/4/zlcoTjd4bnK4hQIGyPGOFiC6ATdfIZzVybrUL3tYA1enSh1lBqVh4KVuq9q
LkqaBzpNelbwXcSnd5ohLgC/thqMfuYjHnUT1sVEt5uQRL4XA== 
");


my $sig_nsec2_ldns=Net::DNS::RR->new("
itema.with.caps.example.com.    300     IN      RRSIG   NSEC RSASHA1 5 300 20380
119031407 20070309133715 6227 example.com. vvoRDdVtmRhnePyN9Fcm4+vUN7WR4VV6BP68o
oHwqmYcllKB6dW1blPupRlVknxhpdGuiSt9D6AhBRFxZNKYhC0mPECHhIXD7wdM/ubMw5ebvRX25DdNy
JmVeA1Dz2/mJDgId7reofns8AlFL0xgx5OytIQdiA8HVJqJqDOr3EQsnkhMZ575icJIuDwws7IHNDDZD
8QmEAw4RT/+b8bq3VkAKT6XHiFXBvpfMRHw/W3xOfJgYKckZAku2wSt8caWDooneIOUQxrEG5PR+jtHq
zVSxaZtgZ0t9ZR2BPDjgXg3F4kxDetFzqSfjg1fhs+dD9nIn6mGmvNOL71l8vauIA==
");



my $data=[$nsec1];
ok($sig_nsec1->verify($data, $dnskey),"Data did  validate") || diag $sig_nsec1->vrfyerrstr;


my $data2=[$nsec2];
ok($sig_nsec2->verify($data2, $dnskey),"Data validated") || diag $sig_nsec2->vrfyerrstr;

#diag "PERL VERSION $]";
#diag "TIME::Local VERSION $Time::Local::VERSION";
SKIP:{
    skip "Time::Local seems to check on unix time use beyond 2032", 2 if $Time::Local::VERSION > 1.11;
    ok(! $sig_nsec1_ldns->verify($data, $dnskey),"Data did not validate (now generated with 'broken signer')") || diag $sig_nsec1_ldns->vrfyerrstr;



    $data2=[$nsec2];
    ok($sig_nsec2_ldns->verify($data2, $dnskey),"Data validated") || diag $sig_nsec2_ldns->vrfyerrstr;
}




my $UUencodedPacket="
1e 71 85 00 00 01 00 00  00 04 00 05 05 69 74 65 
6d 61 04 77 69 74 68 04  63 61 70 73 07 65 78 61 
6d 70 6c 65 03 63 6f 6d  00 00 01 00 01 c0 1c 00 
06 00 01 00 00 01 2c 00  2a 03 6e 73 31 c0 1c 04 
6f 6c 61 66 05 64 61 63  68 74 03 6e 65 74 00 77 
83 47 cf 00 00 01 c2 00  00 02 58 00 05 46 00 00 
00 01 2c c0 1c 00 2e 00  01 00 00 01 2c 01 1f 00 
06 05 02 00 00 0e 10 72  98 2e 33 43 6a b0 ea 18 
53 07 65 78 61 6d 70 6c  65 03 63 6f 6d 00 5c 7c 
61 27 63 19 fb 78 6e 3f  24 4b 03 09 96 fa 3a 65 
e3 5d 36 76 ed 16 1f a3  04 28 e2 e8 3c a9 6d 84 
1e f6 33 cb 66 62 17 9f  1a 69 3b d9 e9 59 dd 88 
64 14 9f 3d f9 38 43 fe  43 de 80 d9 7d 8a 50 1f 
ae 7c 17 5e 1a ce 51 eb  4a 8a f0 f4 5e a7 0c 50 
07 f3 88 ef 8b 8f 6d 6f  dd 9f 25 4c dd eb fd 99 
89 09 c2 d8 69 aa d2 d3  e8 be 00 fd c4 9f 3f 92 
4f 4c 19 8e 3d 7d 1a bd  6a 38 ed c5 18 57 21 b7 
88 6c 46 4d fe 5d 2d 24  ab f2 71 30 34 a3 a5 d9 
be e4 f7 ab 62 90 35 b6  dd 9c 83 f4 93 fe 7c 7e 
2d 97 e3 5d a8 65 e6 b4  43 e0 06 ca 92 82 13 86 
a3 50 44 58 72 53 b2 7e  28 2c c2 de 8e 25 70 86 
66 77 8a d6 f6 b9 e3 d2  4d 10 ce c8 f2 cb d9 d5 
c8 10 f0 b5 ee bc d8 39  4a 82 b4 ea f7 f9 9a 05 
6e 1d a4 07 15 f9 1a 70  03 f3 7c 9d e7 6c cc 2e 
1c 16 cf bf c0 3a 37 4e  c8 20 66 00 ac 59 c0 0c 
00 2f 00 01 00 00 01 2c  00 28 05 69 74 65 6d 62 
07 77 69 74 68 6f 75 74  04 63 61 70 73 07 65 78 
61 6d 70 6c 65 03 63 6f  6d 00 00 06 00 00 80 00 
00 03 c0 0c 00 2e 00 01  00 00 01 2c 01 1f 00 2f 
05 05 00 00 01 2c 72 98  2e 33 43 6a b0 ea 18 53 
07 65 78 61 6d 70 6c 65  03 63 6f 6d 00 cd bd 75 
af 09 b1 ae 06 df cc 85  55 d1 5f f0 94 97 40 be 
6c b5 a9 9b 9e 43 51 7b  51 3b 48 99 ac 5b c5 90 
ab 4d e1 a6 5b 22 44 de  26 40 31 0a 76 9b ec 9b 
4e b5 34 c0 85 c2 3c 27  7c 90 6f 5b 05 05 09 25 
33 b4 da d9 c9 44 3b 22  54 ec 49 8d 59 12 5d b2 
ce 01 99 7d c9 c0 53 fc  0f bd eb 78 40 c3 b3 12 
d2 81 f7 17 1a de c9 71  f0 3d 7a e4 f1 51 c4 39 
4e e4 64 53 4e 18 7b 10  66 eb 65 3d 66 ee 71 b3 
17 fd 1a cf f0 7b 28 de  1d 5a 67 a4 a9 84 0d ca 
e1 ae 14 31 59 e5 a5 ec  db d9 3f a9 5a a5 7c 9c 
ce 52 8f 4c 75 50 62 19  14 b3 29 5a 91 74 a3 f7 
4f 32 c7 73 69 6e 2f 8b  34 e4 0f 24 9e bb 40 57 
0d c5 8e d9 e2 0f 74 a4  dd f3 4c 87 4c 84 e1 f0 
9a ef 24 1d 6c a6 ea 46  92 80 0d d9 58 0d 29 35 
19 df 01 39 a1 e0 1d 50  fe d2 9f b4 cf 4c b9 e4 
6b ca ef a3 17 2a 9b a8  6a 76 b6 2c b9 c1 e0 00 
30 00 01 00 00 0e 10 01  06 01 01 03 05 01 03 d4 
8a cc cc 30 08 b7 e9 a8  31 fd 5f bb 4f 0f 79 97 
c3 d8 9a 85 63 1d 6b ce  2b 1c 7f d2 21 fc 64 4d 
ec 74 4a 90 9d c0 9e 26  0e c8 55 0f 8b 35 64 8f 
f6 64 ff 07 6e 9e 41 be  56 67 62 0a 17 33 45 41 
33 0d 8b ab a6 fb 28 77  9f 2b 5a cf 03 b0 3b 1d 
34 d9 51 a7 c2 96 30 9d  41 55 dd b6 79 05 c8 16 
0b cc 2b 53 35 46 80 25  48 bd 7f 9b 7a c6 6b 21 
73 18 eb 4c ab 89 1a 90  a8 d1 8e 0e 72 a8 d9 3e 
b3 61 ec 1f 0b 0e 25 63  14 4a 61 3e 91 a8 0d 32 
f2 72 6a c8 b4 66 79 9d  27 60 fe ae bc 36 23 1c 
4b bb 9a a5 1f 5c 1c de  64 d3 32 dd 68 12 09 36 
d0 a0 af d1 69 24 7b 69  d4 e0 4d ee 6d f7 bd 9c 
e7 50 e2 ed 30 b0 c6 90  f3 09 f0 0a b8 f3 e4 96 
20 4c f5 9d 31 e2 00 b4  01 97 ce e4 c6 b4 a7 e7 
61 7f 69 3b c1 f9 7c 9b  cc 44 38 43 09 21 32 e8 
a3 2f 3c 36 1f ae d9 cf  47 17 5b 70 d2 76 87 c1 
e0 00 30 00 01 00 00 0e  10 01 06 01 00 03 05 01 
03 da a0 75 bf 9c 2d 1f  8f d1 ee 09 6d e1 00 24 
86 88 fd 00 90 f4 b7 75  01 57 0e 51 14 8e fd 68 
ad bb 71 d3 a4 cc 99 52  86 2b 92 b9 eb 83 92 77 
a5 02 7f 86 50 12 ed 82  30 f4 80 50 51 87 11 9b 
80 34 a6 06 c1 98 74 93  f1 de a1 53 5e a2 6d 4b 
dc db 78 b5 52 e2 18 cc  eb 3d 0b 24 cd e2 bc b2 
bd 4d 2a 0a 85 99 c9 10  96 53 16 77 4a 1b f1 47 
7a 9e a7 90 2c 7b d7 42  0b f5 88 75 f7 76 90 48 
3c b6 1b 44 2c ee 7a a0  b9 93 4f 40 3e 5d b9 3e 
02 63 8e b7 b2 45 7a f1  a1 db e8 8a 26 8b 1e 97 
4b e4 db 4c d9 2f 5e a2  4d b3 9a e4 69 61 04 85 
d4 b4 cd 7d 6c 18 f4 29  20 2f 4d 7b 67 f6 6f d3 
44 9b 72 84 cc fd e4 d7  3e a8 a3 1a d5 21 87 a5 
17 d6 05 fc f7 26 de ca  3b 5f 70 66 e6 4d c0 7e 
23 bf 4d ca 46 56 a1 d7  4e f3 3c b3 05 7c f3 7c 
5c 2d b0 0b ab ca 34 3f  1c 56 b9 af 89 ab 6e 19 
09 c1 e0 00 2e 00 01 00  00 0e 10 01 1f 00 30 05 
02 00 00 0e 10 72 98 2e  33 43 6a b0 ea 18 53 07 
65 78 61 6d 70 6c 65 03  63 6f 6d 00 82 7f 52 b3 
ef 94 9b 28 76 7e cd 95  f5 3c f7 cf a7 2e a6 01 
7b c8 99 64 f7 86 91 9f  52 dc a4 9e 42 73 d0 d1 
e5 fd 83 56 c8 77 e5 17  03 72 19 c1 f8 60 09 0f 
c3 49 43 29 a7 eb 41 84  8b e9 e6 69 c1 68 94 24 
6f bd b0 58 73 45 d4 70  39 20 c1 d8 65 5e 8c 7b 
d9 61 6c 7d 02 0d 34 21  94 58 fa f2 13 a3 bb d6 
a0 e3 3e b1 fd 09 a3 73  9b ee 8b f3 4d c7 09 a8 
6d dc 7f 72 c7 8b 82 6e  3f 8b da 11 99 4d 2d 3b 
76 d6 90 23 f8 84 6c 7c  9b 77 7a 6f 8d 35 e0 f3 
37 44 77 9c ec d0 9b b5  f7 f1 13 ec b9 ab 3f d6 
b6 05 3f cc 76 0a 6f 7a  ab f5 1a fe 91 05 1d a0 
9f 45 ea c3 b4 ab 0a 15  c4 c7 68 0b cc 57 a8 d1 
65 18 c9 46 3d 4d b3 d0  60 d3 79 76 48 cf 26 ba 
dc aa 0c 1d a1 60 c7 9d  e8 69 c2 0f 6a 8c ff 14 
32 6b c3 bb d1 00 88 96  2f cf b8 0c b8 bb 6e e9 
38 b9 c7 fe 6b af a0 06  2e 52 f7 26 c5 2f 00 2e 
00 01 00 00 0e 10 01 1f  00 30 05 02 00 00 0e 10 
72 98 2e 33 43 6a b0 ea  9e ac 07 65 78 61 6d 70 
6c 65 03 63 6f 6d 00 40  11 fa b5 16 85 0b 01 66 
67 78 a6 ce bb 87 89 a6  a0 de 2c 3c 71 f3 f1 02 
17 6a 69 0c ec 49 d2 3b  28 6b fc e6 0b 8b 64 24 
d3 18 57 16 b9 25 d6 e3  48 3a 85 da f0 10 ed 5a 
8c 94 0d 2e 41 c3 06 ae  c5 45 06 b2 b4 16 a2 f7 
0e 97 6b d5 ce dc c3 cd  09 9d 5e 68 3a 66 5f c9 
9e f5 b0 f3 ca 60 5b 55  04 e9 3d eb b0 5d 60 43 
1b ac 1e ac e5 a8 19 12  6b 18 5e f5 b0 c9 a0 48 
02 72 70 fa 57 97 ff 49  14 a5 dc 33 b2 9e 7c 14 
75 2a df e9 1d d3 67 be  52 a1 f1 69 ec 3f a6 ff 
c9 c4 dd 7b 06 ac df 41  a3 35 50 a0 50 a7 9e 90 
66 99 7f a0 ca cf 85 6a  28 f1 c1 1a 10 f7 2a 04 
a8 bd a1 47 c3 f0 0f 49  a0 a8 95 76 d9 95 50 56 
c1 66 e8 45 46 ee 2d c6  94 b2 5f b1 2c f4 3d ab 
28 2a 65 47 94 cc b2 63  ac a6 00 63 ff 51 72 5e 
fd f8 67 45 8b 44 2f 00  ed 8c f0 77 a7 99 42 77 
39 99 d1 b1 83 ef 48 00  00 29 10 00 00 00 80 00 
00 00                                            
";

   
$UUencodedPacket =~ s/\s*//g;
my $packetdata = pack('H*',$UUencodedPacket);
my $packet     = Net::DNS::Packet->new(\$packetdata);
#$packet->print;






