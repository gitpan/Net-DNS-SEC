#
# $Id: SEC.pm,v 1.13 2004/04/23 14:35:16 olaf Exp $
#

package Net::DNS::SEC;
use Net::DNS;

use Carp;
use strict;
use vars qw($VERSION);
$VERSION = '0.11_4';


=head1 NAME

Net::DNS::SEC - DNSSEC extensions to Net::DNS

=head1 SYNOPSIS

C<use Net::DNS>;

Net::DNS::SEC contains some code inherited by DNSSEC related RR
classes.

=head1 DESCRIPTION

The Net::DSN::SEC package provides the resource records that are
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


=head1 Functions

These functions are inherited by relevant Net::DNS::RR classes.

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
L<Net::DNS::RR::NSEC>, L<Net::DNS::RR::DS>.

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








