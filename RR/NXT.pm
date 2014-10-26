package Net::DNS::RR::NXT;

# $Id: NXT.pm,v 1.3 2002/06/17 14:36:57 olaf Exp $

use strict;
use vars qw(@ISA $VERSION);
use Carp;

use Net::DNS;
use Net::DNS::Packet;


use Carp;

@ISA = qw(Net::DNS::RR);
$VERSION = do { my @r=(q$Revision: 1.3 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };

sub new {
    my ($class, $self, $data, $offset) = @_;
    
    if ($self->{"rdlength"} > 0) {
	my($nxtdname,$nxtoffset) = 
	  Net::DNS::Packet::dn_expand($data, $offset);

	$self->{"nxtdname"} = "$nxtdname";

	my $typebm =substr($$data,$nxtoffset,
				 $self->{"rdlength"}-
				 $nxtoffset+$offset);

	$self->{"typebm"}=$typebm;
	$self->{"typelist"} = join " " 
	    ,  _typebm2typestr($typebm);
    }
    
    return bless $self, $class;
}

sub new_from_string {
    my ($class, $self, $string) = @_;
    if ($string) {
	$string =~ tr/()//d;
	$string =~ s/;.*$//mg;
	my ($nxtdname) = 
	    $string =~ /^\s*(\S+)\s+/;
	my @nxttypes = split /\s+/ , $';       # everything after last match...
	
	$self->{"nxtdname"}= lc($nxtdname) ;
	$self->{"typelist"}= join " " ,@nxttypes ;
	$self->{"typebm"}=_typestr2typebm(@nxttypes);
	
    }
    return bless $self, $class;
}


sub rdatastr {
	my $self = shift;
	my $rdatastr;

	if (exists $self->{"nxtdname"}) {
	    $rdatastr  = $self->{nxtdname};
	    $rdatastr .= "  "  . "$self->{typelist}";
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}

sub rr_rdata {
    my ($self, $packet, $offset) = @_;
    my $rdata = "" ;
    if (exists $self->{"nxtdname"}) {
	# Compression used here... 
	$rdata = $packet->dn_comp($self->{"nxtdname"},$offset);
	$rdata .= $self->{"typebm"};
    }
    
    return $rdata;
    
}



sub _canonicalRdata {
    # rdata contains a compressed domainname... we should not have that.
	my ($self) = @_;
	my $rdata;

	$rdata=$self->_name2wire($self->{"nxtdname"});
	$rdata .= $self->{"typebm"};	
	return $rdata;
}


sub _typestr2typebm {
    # RFC2535 5.1 needs the typebm
    # This needs to check for values > 127....

    # Sets a bit for every qtype in the input array.
    # Minimum bitmaplenght 4 octets because NXT (30) is allways there
    # may be longer but trailing all zero octets should be dropped.

    my (@typelist, @typebitarray);
    @typelist= @_;
    for(my $i=0;$i < @typelist; $i++){
	$typebitarray[$Net::DNS::typesbyname{uc($typelist[$i])}]=1;
    }
    
    my $finalsize;
    if ( @typebitarray % 4){
	use integer;
	$finalsize = 8 * ((@typebitarray / 8)  + 1);
    }
    for (my $i=0;$i< $finalsize; $i++){
	$typebitarray[$i]=0 if ! defined $typebitarray[$i];
    }
    my $typebm= pack("B$finalsize",join "", @typebitarray );
    return $typebm

}

sub _typebm2typestr {
    # RFC2535 5.1 needs the typebm
    # This needs to check for values > 127....
    my @typebm=split //, unpack("B*", shift);  # bit representation in array
    my @typelist;
    carp "Cannot deal with qtype > 127" 
	if ($#typebm > 127);
    
    my($foo);
    foreach $foo (sort { $a <=> $b } keys(%Net::DNS::typesbyval)  ){
	next if $foo > $#typebm;           # Skip larger aray vallues.
	@typelist=(@typelist,$Net::DNS::typesbyval{$foo}) if 
	    ($typebm[$foo] eq "1");
    }

    return @typelist;
}


1;


=head1 NAME

Net::DNS::RR::NXT - DNS NXT resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for DNS Address (NXT) resource records.

=head1 METHODS

=head2 nxtdname

    print "nxtdname" = ", $rr->nxtdname, "\n";

Returns the RR's next domain name field.


=head2 typelist

    print "typelist" = ", $rr->typelist, "\n";

Returns a string with the list of qtypes for which data exists for
this particular label.



=head2 typebm

    print "typebm" = " unpack("B*", $rr->typebm), "\n";

Same as the typelist but now in a representation  bitmap as in 
specified in the RFC. This is not the kind of method you will need
on daily basis.

=head1 COPYRIGHT

Copyright (c) 2001  RIPE NCC.  Author Olaf M. Kolkman <net-dns-sec@ripe.net>

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO EVENT SHALL
AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY
DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


Based on, and contains, code by Copyright (c) 1997 Michael Fuhr.



=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::Resolver>, L<Net::DNS::Packet>,
L<Net::DNS::Header>, L<Net::DNS::Question>, L<Net::DNS::RR>,
RFC 2435 Section 5

=cut
