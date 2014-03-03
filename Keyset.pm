package Net::DNS::Keyset;

#
# $Id: Keyset.pm 1171 2014-02-26 08:56:52Z willem $
#
use vars qw($VERSION);
$VERSION = (qw$LastChangedRevision: 1171 $)[1];


=head1 NAME

Net::DNS::Keyset - DNSSEC Keyset object class


=head1 SYNOPSIS

    use Net::DNS::Keyset;


=head1 DESCRIPTION

A keyset is an "administrative" unit used for DNSSEC maintenance.

The bind dnssec-signzone tool uses it to generate DS records. This class
provides interfaces for creating, reading and parsing keysets.

Note that this class is still being developed. Attributes and methods are
subject to change.

=cut


use strict;
use Carp;
use File::Spec::Functions;

require Net::DNS::SEC;
require Net::DNS::ZoneFile;

use vars qw ($keyset_err);

my $debug = 0;


sub new {
	my ( $class, $arg1, $arg2 ) = @_;

	my $ref1 = ref($arg1);
	return &_new_from_file unless $ref1;

	if ( $ref1 eq 'ARRAY' ) {
		return &_new_from_keys unless ref($arg2);
		return &_new_from_keys_sigs;
	}

	return &_new_from_packet if $ref1 eq 'Net::DNS::Packet';

	croak 'Could not parse argument list';
}


=head2 new (from file)

    $keyset = Net::DNS::Keyset->new( $filename );
    $keyset = Net::DNS::Keyset->new( $filename, $directory );

Constructor method which reads the specified keyset file and returns a
keyset object.

The optional second argument specifies the filename base directory.

Sets $Net::DNS::Keyset::keyset_err and returns undef on failure.

=cut

sub _new_from_file {
	my ( $class, $file, $path ) = @_;
	$file = catfile( $path, $file ) if $path && !file_name_is_absolute($file);

	my @rr  = new Net::DNS::ZoneFile($file)->read;

	return $class->_new_from_keys_sigs( \@rr, \@rr );
}


=head2 new (by signing keys)

    $keyset = Net::DNS::Keyset->new( \@keyrr, $privatekeypath );

Creates a keyset object from the keys provided through the reference to an
array of Net::DNS::RR::Key objects.

The method will create and self-sign the whole keyset. The private keys as
generated by the BIND dnssec-keygen tool are assumed to be in the current
directory or, if specified, the directory indicated by $privatekeypath.

Sets $Net::DNS::Keyset::keyset_err and returns undef on failure.

=cut

sub _new_from_keys {
	my ( $class, $keylist, $keypath ) = @_;

	my @sigrr;
	foreach my $key ( grep $_->type eq 'DNSKEY', @$keylist ) {
		my $keyname = $key->privatekeyname;
		my $keyfile = $keypath ? catfile( $keypath, $keyname ) : $keyname;
		push @sigrr, Net::DNS::RR::RRSIG->create( $keylist, $keyfile );
	}

	return $class->_new_from_keys_sigs( $keylist, \@sigrr );
}


=head2 new (from key and sig RRsets)

    $keyset = Net::DNS::Keyset->new( \@keyrr, \@sigrr );

Creates a keyset object from the keys provided through the references
to arrays of Net::DNS::RR::DNSKEY and Net::DNS::RR::RRSIG objects.

Sets $Net::DNS::Keyset::keyset_err and returns undef on failure.

=cut

sub _new_from_keys_sigs {
	my ( $class, $key_ref, $sig_ref ) = @_;

	my @keyrr = grep $_->type eq 'DNSKEY', @$key_ref;
	my @sigrr = grep $_->type eq 'RRSIG',  @$sig_ref;

	my $keyset = bless {keys => \@keyrr, sigs => \@sigrr}, shift;

	return $keyset->verify ? $keyset : undef;
}


=head2 new (from Packet)

    $res = Net::DNS::Resolver->new;
    $res->dnssec(1);
   
    $packet = $res->query ( "example.com", "DNSKEY", "IN" );

    $keyset = Net::DNS::Keyset->new( $packet )

Creates a keyset object from a Net::DNS::Packet that contains the answer
to a query for the apex key records.

This is the method you should use for automatically fetching keys.

Sets $Net::DNS::Keyset::keyset_err and returns undef on failure.

=cut

sub _new_from_packet {
	my ( $class, $packet ) = @_;
	my @rrset = $packet->answer;
	return $class->_new_from_keys_sigs( \@rrset, \@rrset );
}


=head2 keys

    @keyrr = $keyset->keys;

Returns an array of Net::DNS::RR::Key objects

=cut

sub keys {
	my $self = shift;
	return @{$self->{keys}};
}


=head2 sigs

    @keyrr = $keyset->sigs;

Returns an array of Net::DNS::RR::Sig objects

=cut

sub sigs {
	my $self = shift;
	return @{$self->{sigs}};
}


=head2 extract_ds

    @ds = $keyset->extract_ds;

Extracts DS records from the keyset. Note that the keyset will be verified
during extraction: All keys will need to have a valid self-signature.

=cut

sub extract_ds {
	my $self = shift;
	my @ds;
	@ds = map Net::DNS::RR::DS->create($_), $self->keys if $self->verify;
	return @ds;
}


=head2 verify
    
    die $Net::DNS::Keyset::keyset_err unless $keyset->verify;

If no arguments are given:

    - Verifies if all signatures present verify the keyset.
    - Verifies if there are DNSKEYs with the SEP flag set, there is at
      least one RRSIG made using that key.
    - Verifies that if there are no DNSKEYS with the SEP flag set there
      is at least one RRSIG made with one of the keys from the keyset.

If an argument is given, it is should be the KEYID of one of the keys in
the keyset which will be verified using the corresponding RRSIG.

If verification fails the method sets $Net::DNS::Keyset::keyset_err and
returns 0.

If verification succeeds an array is returned with the key-tags of the
keys for which signatures verified.

=cut

sub verify {
	my ( $self, $keyid ) = @_;

	my @keys = $self->keys;

	my %keys;
	push( @{$keys{$_->keytag}}, $_ ) foreach @keys;

	my @sigs = $self->sigs;

	$keyset_err = '';
	unless (@sigs) {
		$keyset_err = 'No signature found';
	} elsif ($keyid) {
		@sigs = grep $_->keytag == $keyid, @sigs;
		$keyset_err = "No signature made with $keyid found" unless @sigs;
	} elsif ( my @sepkeys = grep $_->sep, @keys ) {
		my %sepkey = map { ( $_->keytag => $_ ) } @sepkeys;
		$keyset_err = 'No signature found for key with SEP flag'
				unless grep $sepkey{$_->keytag}, @sigs;
	}

	my %names = map { ( $_->name => $_ ) } @keys, @sigs;
	my @names = CORE::keys %names;
	$keyset_err = "Different names in the keyset: @names" if scalar(@names) > 1;

	foreach my $sig (@sigs) {
		my $keytag = $sig->keytag;
		my ( $key, $collision ) = @{$keys{$keytag}};
		next if $sig->verify( \@keys, ( $collision ? $keys{$keytag} : $key ) );
		my $vrfyerr = $sig->vrfyerrstr;
		my $signame = $sig->signame;
		print "$vrfyerr on key $signame $keytag" if $debug;
		$keyset_err .= "\n" if $keyset_err;
		$keyset_err .= "$vrfyerr on key $signame $keytag ";
	}
	return 0 if $keyset_err;

	$keyset_err = 'No Error';
	my @tags_verified = map $_->keytag, @sigs;
	return @tags_verified;
}


=head2 string
    
    $string = $keyset->string;

Returns a string representation of the keyset.

=cut

sub string {
	my $self = shift;
	return join "\n", map $_->string, ( $self->keys, $self->sigs );
}


=head2 print

    $keyset->print;		# similar to print( $keyset->string )

Prints the keyset.

=cut

sub print {
	my $self = shift;
	$_->print foreach ( $self->keys, $self->sigs );
}


=head2 writekeyset

    $keyset->writekeyset;
    $keyset->writekeyset( $path );
    $keyset->writekeyset( $prefix );
    $keyset->writekeyset( $prefix, $path );

Writes the keyset to a file named "keyset-<domain>." in the current
working directory or directory defined by the optional $path argument.

The optional $prefix argument specifies the prefix that will be
prepended to the domain name to form the keyset filename.

=cut

sub writekeyset {
	my $self = shift;
	my ( $arg1, $arg2 ) = @_;
	my $path = file_name_is_absolute($arg1) ? shift : $arg2 if $arg1;
	my $prefix = shift || 'keyset-';

	my @keysetrr   = ( $self->keys, $self->sigs );
	my $domainname = $keysetrr[0]->name;
	my $keysetname = "$prefix$domainname.";
	my $filename   = $path ? catfile( $path, $keysetname ) : $keysetname;
	$filename =~ s/[.]+/\./;	## avoid antisocial consequences of $path with ..
	open( KEYSET, "> $filename" ) || croak "Could not open $filename for writing";
	print KEYSET $_->string, "\n" foreach ( $self->keys, $self->sigs );
	return 1;
}


1;

__END__


=head1 COPYRIGHT

Copyright (c) 2002 RIPE NCC.  Author Olaf M. Kolkman

Portions Copyright (c) 2014 Dick Franks

All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of the author not be used
in advertising or publicity pertaining to distribution of the software
without specific prior written permission.

THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS; IN NO
EVENT SHALL AUTHOR BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

=cut

