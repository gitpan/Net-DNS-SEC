#!/usr/bin/perl  -sw -I./blib/lib
use Net::DNS;
use Net::DNS::Keyset;
use strict;
my $res;
my $packet;
my $keyset;


my $domain=shift;
my $nameserver=shift;

die "At least one argument needed " if !defined $domain;


$res = Net::DNS::Resolver->new;

$res->dnssec(1);
$res->nameservers($nameserver) if defined $nameserver;
$packet = $res->query($domain, 'KEY', 'IN');

die "No results for query $domain KEY" if ! defined $packet;

$keyset=Net::DNS::Keyset->new($packet) ;

if ( ! $keyset ){
    print $Net::DNS::Keyset::keyset_err;
    return 0;
}


# Print DS records to STD out
#
my @ds=$keyset->extract_ds;
foreach my $ds ( @ds ) {
    $ds->print;
}

# write keyset in current dir.
#
$keyset->writekeyset;

1;

__END__




=head1 NAME

    getkeyset.pl - DS extraction demo

=head1 SYNOPSIS


    getkeyset.pl <domain> [auth_nameserver]

=head1 DESCRIPTION

The program queries for the key-set of 'domain'. Spits out the DS
records and writes the keyset to the current directory.

If the second argument is specified the query is performed to that
nameserver.



=head1 TODO

This is only a demonstration program to show how the interface can be used.


=head1 COPYRIGHT

Copyright (c) 2002 RIPE NCC.  Author Olaf M. Kolkman
<net-dns-sec@ripe.net>

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO
EVENT SHALL AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

=cut




=cut

