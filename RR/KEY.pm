package Net::DNS::RR::KEY;

# $Id: KEY.pm,v 1.2 2002/06/04 12:14:18 olaf Exp $

use strict;
use vars qw(@ISA $VERSION);

use Net::DNS::SEC;
use MIME::Base64;
use Carp;

@ISA = qw(Net::DNS::RR);
$VERSION = do { my @r=(q$Revision: 1.2 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };
sub new {
    my ($class, $self, $data, $offset) = @_;
    if ($self->{"rdlength"} > 0) {
	
	my $offsettoprot=$offset+2;
	my $offsettoalg=$offset+3;
	my $offsettokey=$offset+4;
	
	$self->{"flags"}=unpack("n",substr($$data,$offset,2));
	$self->{"protocol"}=unpack("C",substr($$data,$offsettoprot,1));
	$self->{"algorithm"}=unpack("C",substr($$data,$offsettoalg,1));
	my $keymaterial=substr($$data,$offsettokey,$self->{"rdlength"}-4);
	$self->{"keybin"}=($keymaterial);
	$self->{"key"}= encode_base64($keymaterial);
	
	setkeytag($self);	
    }
    return bless $self, $class;
}





sub new_from_string {
	my ($class, $self, $string) = @_;


	if ($string) {
		$string =~ tr/()//d;
		$string =~ s/;.*$//mg;
		my ($flags, $protocol, $algorithm) = 
		    $string =~ /^\s*(\S+)\s+(\S+)\s+(\S+)/;
		my $key=$';       # everything after last match...
		$key =~ s/\s*//g;
		$self->{"flags"}=$flags;
		$self->{"algorithm"}=$algorithm;
		$self->{"protocol"}=$protocol;
		my $keymaterial=decode_base64($key);
		$self->{"keybin"}=($keymaterial);
		$self->{"key"}=$key;
		
		setkeytag($self);
	    }
	return bless $self, $class;
}



sub rdatastr {
	my $self = shift;
	my $rdatastr;
	if (exists $self->{"flags"}) {
	    $rdatastr  = $self->{flags};
	    $rdatastr .= "  "  . "$self->{protocol}";
	    $rdatastr .= "  "  . "$self->{algorithm}";
	    $rdatastr .= " ( \n" ;
	    # do some nice formatting
	    my $keystring=$self->{key};
	    $keystring =~ s/\n//g;
	    $keystring =~ s/(\S{36})/$1\n\t\t\t/g;
	    $rdatastr .=  "\t\t\t".$keystring;
	    $rdatastr .= " \n\t\t\t) ; Key ID = "  . "$self->{keytag}";
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}

sub rr_rdata {
    my $self = shift;
    
    my $rdata;
    if (exists $self->{"flags"}) {
	$rdata= pack("n",$self->{"flags"}) ;
	$rdata.=
	    pack("C2",$self->{"protocol"} 
		     , $self->{"algorithm"}) ;
	$rdata.= $self->{"keybin"}
    }
    return $rdata;
}

sub setkeytag
{
    my $self=shift;
    if (($self->{"flags"} & hex("0xc000") ) == hex("0xc000") ){
	# NULL KEY
	$self->{"keytag"} = 0;
    }elsif ($self->{"algorithm"} == '1'){
	# RFC 2535 4.1.6  most significant 16 bits of the least
	#                 significant 24 bits
	
	my @keystr=split //, $self->{"keybin"};
	my $keysize= $#keystr+1;
	$self->{"keytag"} = (unpack("C",$keystr[$keysize - 3]) << 8) 
	    + unpack("C",$keystr[$keysize - 2]);
	0;
    }else{
	# All others
	# RFC 2535  Appendix C
	my ($ac, $i);
	

	# $self->{"rr_data"} cannot be 
	# used if the object has not been constructed ?!?

	my $rdata= pack("n",$self->{"flags"}) ;   
	$rdata.=
	    pack("C2",$self->{"protocol"} 
		 , $self->{"algorithm"}) ;
	$rdata.= $self->{"keybin"};
	my @keyrr=split //, $rdata;

	for ( $ac=0 , $i=0; $i <= $#keyrr ; $i++ ){
	    $ac += ($i & 1) ? 
		unpack("C",$keyrr[$i]) :
		    unpack("C", $keyrr[$i])<<8;
	}
	$ac += ($ac>>16) & 0xFFFF;
	$self->{"keytag"} =($ac & 0xFFFF);
	0;
    }
    
}





1;


=head1 NAME

Net::DNS::RR::KEY - DNS KEY resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION

Class for DNS Address (KEY) resource records.

=head1 METHODS

=head2 flags

    print "flags" = ", $rr->flags, "\n";

Returns the RR's flags in decimal representation


=head2 protocol

    print "protocol" = ", $rr->protocol, "\n";

Returns the RR's protocol field in decimal representation

=head2 algorithm

    print "algoritm" = ", $rr->algorithm, "\n";

Returns the RR's algorithm field in decimal representation

    1 = MD5 RSA
    2 = DH
    3 = DSA
    4 = Elliptic curve

=head2 key

    print "key" = ", $rr->key, "\n";

Returns the key in base64 representation


=head2 keybin

    $keybin =  $rr->keybin;

Returns the key binary material


=head2 keytag

    print "keytag" = ", $rr->keytag, "\n";

Returns the key tag of the key. (RFC2535 4.1.6)



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
RFC 2435 Section 3

=cut
