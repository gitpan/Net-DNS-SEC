package Net::DNS::RR::SIG::Private;

use vars qw(@ISA $VERSION @EXPORT );

use Net::DNS;
use Carp;

use Crypt::OpenSSL::DSA;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;

use File::Basename;
use MIME::Base64;
use Math::BigInt;
use Time::Local;
use Digest::SHA1 qw (sha1);


require Exporter;

$VERSION = do { my @r=(q$Revision: 1.2 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };


my     $__DepricationWarning=0;
sub new {
    my ($class,  $key_file) = @_;
    my $self={};
    my    ($Modulus,$PublicExponent,$PrivateExponent,$Prime1,
	   $Prime2,$Exponent1,$Exponent2,$Coefficient,
	   $prime_p,$subprime_q,$base_g,$private_val_x,$public_val_y);


    print "Note: Net::DNS::RR::SIG::Private is deprecated use Net::DNS::SEC::Private instaed! " if ! $__DepricationWarning;
    $__DepricationWarning=1;
    bless ($self,$class);
    my $keyname=basename($key_file);
    print "\nKeyname:\t ". $keyname ."\n" if $ debug;

    #Format something like: /Kbla.foo.+001+60114.private'
    # assuming proper file name.
    # We determine the algorithm from the filename.
    if ($keyname =~ /K(.*)\.\+(\d{3})\+(\d*)\.private/){
	$self->{"signame"}=$1;  # withouth trailing .
	$self->{"algorithm"}= 0 + $2; #  Force non-string 
	$self->{"keytag"}=$3;
    }else{
	croak "$keyname does not seem to be a valid private key\n";
    }



    open (KEYFH, "<$key_file" ) || croak "Cannot open keyfile: $key_file";
    while (<KEYFH>) {
	if (/Private-key-format: (v\d*\.\d*)/) {
	    if ($1 ne "v1.2") {
		croak "Private Key Format not regognized";
	    }
	}elsif	    (/^Algorithm:\s*(\d*)/) {
	    if ($1 != 1 && $1 != 3 && $1 != 5) {
		croak "Key $key_file algorithm is not RSA or DSA (those are the only implemented algorithms) ";
	    }
	    
	} elsif (/^Modulus:\s*(\S+)/) {				#RSA 
	  $Modulus=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^PublicExponent:\s*(\S+)/) {

	  $PublicExponent=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^PrivateExponent:\s*(\S+)/) {
	    $PrivateExponent=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Prime1:\s*(\S+)/) {
	    $Prime1=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Prime2:\s*(\S+)/) {
	    $Prime2=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Exponent1:\s*(\S+)/) {
	    $Exponent1=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Exponent2:\s*(\S+)/) {
	    $Exponent2=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));
	} elsif (/^Coefficient:\s*(\S+)/) {
	    $Coefficient=Crypt::OpenSSL::Bignum->new_from_bin(decode_base64($1));

	} elsif (/^Prime\(p\):\s*(\S+)/) {				#DSA
	    $prime_p=decode_base64($1);
	} elsif (/^Subprime\(q\):\s*(\S+)/) {
	    $subprime_q=decode_base64($1);
	} elsif (/^Base\(g\):\s*(\S+)/) {
	    $base_g=decode_base64($1);
	} elsif (/^Private_value\(x\):\s*(\S+)/) {
	    $private_val_x=decode_base64($1);
	} elsif (/^Public_value\(y\):\s*(\S+)/) { 
	    $public_val_y=decode_base64($1);
	}
    }
    close(KEYFH);

    if ($self->{"algorithm"} == 1 || $self->{"algorithm"} == 5) {  #RSA


      $self->{'privatekey'}=Crypt::OpenSSL::RSA-> 
	new_key_from_parameters(
				$Modulus,
				$PublicExponent,
				$PrivateExponent);
    }elsif ($self->{"algorithm"} == 3){  #DSA
	my $private_dsa = Crypt::OpenSSL::DSA->new();
	$private_dsa->set_p($prime_p);
	$private_dsa->set_q($subprime_q);
	$private_dsa->set_g($base_g);
	$private_dsa->set_priv_key($private_val_x);
	$private_dsa->set_pub_key($public_val_y);
	$self->{"privatekey"}=$private_dsa;
    }
    
    return $self;

}




sub algorithm {
    my $self=shift;
    return $self->{'algorithm'};
}


sub privatekey {
    my $self=shift;
    return $self->{'privatekey'};
}


sub keytag {
    my $self=shift;
    return $self->{'keytag'};
}



sub signame {
    my $self=shift;
    return $self->{'signame'};
}



# Little helper function to put a BigInt into a binary (unsigned,
#network order )

sub bi2bin {
    my($p, $l) = @_;
    $l ||= 0;
    my $base = Math::BigInt->new("+256");
    my $res = '';
    {
        my $r = $p % $base;
        my $d = ($p-$r) / $base;
        $res = chr($r) . $res;
        if ($d >= $base) {
            $p = $d;
            redo;
        }
        elsif ($d != 0) {
            $res = chr($d) . $res;
        }
    }
    $res = "\0" x ($l-length($res)) . $res
        if length($res) < $l;
    $res;
}



1;



=head1 NAME

Net::DNS::RR::SIG::Private - DNS SIG Private key object

=head1 SYNOPSIS

C<use Net::DNS::RR::SIG::Private>;
my $private=Net::DNS::RR::SIG::Private->new($keypath);

=head1 DESCRIPTION

     !!!DEPRECATED use Net::DNS::SEC::Private instead!!!

Class containing a the private key as read from a dnssec-keygen
generate zonefile. The class is written to be used only in the context
of the Net::DNS::RR::SIG create method. This class is not designed to
interact with any other system.



=head1 METHODS

=head2 new

$private->new("/home/foo/ Kexample.com.+001+11567.private")

Creator method. The argument is the full path to a private key
generated by the BIND dnssec-keygen tool. Note that the filename contains
information about the algorithm and keyid.


=head2 private

$private->private

Returns the private key material. This is either a Crypt::OpenSSL::RSA
or Crypt::OpenSSL::DSA object. This is really only relevant to the
Net::DNS::RR::SIG class.


=head2  algorithm, keytag, signame
 
 $private->algorithm
 $private->keytag
 $private->signame

Returns components as determined from the filename and needed by
Net::DNS::RR::SIG.


=head1 TODO

Add a genereate method that will generate a key pair.









=head1 COPYRIGHT

Copyright (c) 2002, 2003  RIPE NCC.  Author Olaf M. Kolkman <net-dns-sec@ripe.net>

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


This code uses Crypt::OpenSSL which uses the openssl library


=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::SIG>, L<Crypt::OpenSSL::RSA>,L<Crypt::OpenSSL::DSA>
RFC 2435 Section 4, RFC 2931.

=cut
