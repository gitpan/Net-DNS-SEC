#
# $Id: SEC.pm,v 1.16 2004/06/04 16:06:48 olaf Exp $
#

use strict;



package Net::DNS::SEC;
use Net::DNS;

use Carp;
use strict;
use Exporter;
use vars qw($VERSION @EXPORT_OK @ISA);
@ISA=qw(Exporter);
$VERSION = '0.12';

@EXPORT_OK= qw (
              key_difference
              verify_selfsig
               );


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DNS

=head1 SYNOPSIS

C<use Net::DNS>;

Net::DNS::SEC contains some code inherited by DNSSEC related RR
classes.

=head1 DESCRIPTION

The Net::DSN::SEC suit provides the resource records that are
needed for Secure DNS (RFC2535). DNSSEC is a protocol that is still
under development.

We have currently implemented the RFC2535 specifications with addition
of the 'delegation-signer' draft, the "typecode roll draft" and SIG0
support. That later is useful for dynamic updates with public keys.

RSA and DSA crypto routines are supported.

For details see Net::DNS::RR::SIG, Net::DNS::RR::KEY,
Net::DNS::RR::NXT Net::DNS::RR::RRSIG, Net::DNS::RR::DNSKEY,
Net::DNS::RR::NSEC and Net::DNS::RR:DS.

Net::DNS will load the modules for the secure RRs when they are
available through the Net::DNS::SEC package.

See Net::DNS for general help.

The Net::DNS::SEC module implements a few class methods used by the other
modules in this suite and a few functions that can be exported.


=head1 Utility functions

Use the following construct if you want to use these functions in your code.

   use Net::DNS::SEC qw( key_difference );



=head2 key_difference

    $result=key_differnece(\@a,\@b,\@result);


Fills @result with all keys in the array "@a" that are not in the
array "@b".

Returns 0 on success or an error message on failure.


=cut


sub key_difference {
    my $a=shift;
    my $b=shift;
    my $r=shift;

    my %b_index;
    foreach my $b_key (@$b){
	return "Second array contains something different than a ".
	    "Net::DNS::RR::DNSKEY objects (".ref($b_key).")" if
	    ref($b_key) ne "Net::DNS::RR::DNSKEY";
	    
	$b_index{$b_key->name."+".$b_key->algorithm."+".$b_key->keytag}++;
    }
    foreach my $a_key (@$a){
	return "First array contains something different than a ".
	    "Net::DNS::RR::DNSKEY objects (".ref($a_key).")" if
	    ref($a_key) ne "Net::DNS::RR::DNSKEY";

	push @$r,$a_key  unless 
	    defined ($b_index{$a_key->name."+".$a_key->algorithm."+".$a_key->keytag});
    }
    return (0);
}


=head1 Class methods

These functions are inherited by relevant Net::DNS::RR classes. They
are not exported.

=head2 algorithm

    $value=Net::DNS::SEC->algorithm("RSA/SHA1");
    $value=$self->algorithm("RSA/SHA1");
    $value=$self->algorithm(5);

    $algorithm=$self->algorithm();
    $memonic=$self->algorithm("mnemonic");



The algorithm method is used to set or read the value of the algorithm
field in Net::DNS::RR::DNSKEY and Net::DNS::RR::RRSIG.

If supplied with an argument it will set the algorithm accordingly, except
when the argument equals the string "mnemonic" the method will return the
mnemonic of the algorithm.

Can also be called as a class method to do Mnemonic to Value conversion.
 


=head1 SEE ALSO

L<perl(1)>, L<Net::DNS>, L<Net::DNS::RR::KEY>, L<Net::DNS::RR::SIG>,
L<Net::DNS::RR::NXT>, L<Net::DNS::RR::DNSKEY>, L<Net::DNS::RR::RRSIG>,
L<Net::DNS::RR::NSEC>, L<Net::DNS::RR::DS>, L<Net::DNS::SEC::Private>.

=cut




sub algorithm {
    my $self=shift;
    my $argument=shift;
    # classmethod is true if called as class method.
    my $classmethod=0;
    $classmethod=1 unless  ref ($self);

    my %algbyname = (
		  "RSA/MD5"		=> 1,		
#		  "DH"                  => 2,           # Not implemented
		  "DSA"                 => 3,
#		  "ECC"                 => 4,           # Not implemented
		  "RSA/SHA1"            => 5,
		  );
    my %algbyval = reverse %algbyname;

    # If the argument is undefined...
    
    if (!defined $argument){
	return if $classmethod;
	return $self->{"algorithm"};
    }

    # Argument has some value...
    $argument =~ s/\s//g; # Remove strings to be kind

    if ($argument =~ /^\d+$/ ){    #Numeric argument.
	carp "$argument does not map to a valid algorithm" unless 
	    exists $algbyval{$argument};
	if ($classmethod){
	    return $argument ;
	}else{
	    return $self->{"algorithm"}=$argument ;
	}
    }else{  # argument is not numeric
	if ($classmethod){
	    carp "$argument does not map to a valid algorithm" unless
		exists $algbyname{uc($argument)};
	    return $algbyname{uc($argument)};
	    
	}else{ # Not a class method..
	    if (lc($argument) eq "mnemonic"){
		return $algbyval{$self->{"algorithm"}};
	    }else{
		carp "$argument does not map to a valid algorithm" unless
		    exists $algbyname{uc($argument)};
		return $self->{"algorithm"}=$algbyname{uc($argument)};
	    }	    
	}

	
    }	
    die "algorithm method should never end here";

	
}








