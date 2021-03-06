#
# $Id: Makefile.PL 1293 2015-01-07 07:42:26Z willem $
#


warn <<AMEN if $] < 5.008;

Net::DNS has been tested with Perl  5.008

The author is confident that this package will work with version 5.6
but not confident that it will work with any earlier version.

The latest version of perl can always be found at:
	http://www.cpan.org/src/latest.tar.gz
AMEN

use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
	NAME		 => 'Net::DNS::SEC',
	VERSION_FROM	 => 'SEC.pm',
	ABSTRACT	 => 'DNSSEC extensions to Net::DNS',
	AUTHOR		 => 'Olaf M. Kolkman <olaf@net-dns.org>',
	LICENSE		 => 'mit',
	MIN_PERL_VERSION => 5.006,
	PREREQ_PM	 => {
		Net::DNS	       => 0.69,
		Crypt::OpenSSL::Bignum => 0.04,
		Crypt::OpenSSL::RSA    => 0.19,
		Crypt::OpenSSL::DSA    => 0.10,
	#	Crypt::OpenSSL::EC     => 0.6,			# optional
	#	Crypt::OpenSSL::ECDSA  => 0.05,			# optional
	#	Digest::BubbleBabble   => 0.01,			# optional
	#	Digest::GOST	       => 0.06,			# optional
		Digest::SHA	       => 5.23,
		File::Spec	       => 0.0,
		MIME::Base32	       => 0.0,
		MIME::Base64	       => 0.0,
		Time::Local	       => 0.0,
		Test::More	       => 0.47,
		},

	PM => { 'Keyset.pm'	   => '$(INST_LIBDIR)/Keyset.pm',
		'SEC.pm'	   => '$(INST_LIBDIR)/SEC.pm',
		'SEC/Private.pm'   => '$(INST_LIBDIR)/SEC/Private.pm',
		'RR/CDNSKEY.pm'	   => '$(INST_LIBDIR)/RR/CDNSKEY.pm',
		'RR/CDS.pm'	   => '$(INST_LIBDIR)/RR/CDS.pm',
		'RR/DLV.pm'	   => '$(INST_LIBDIR)/RR/DLV.pm',
		'RR/DNSKEY.pm'	   => '$(INST_LIBDIR)/RR/DNSKEY.pm',
		'RR/DS.pm'	   => '$(INST_LIBDIR)/RR/DS.pm',
		'RR/KEY.pm'	   => '$(INST_LIBDIR)/RR/KEY.pm',
		'RR/NSEC.pm'	   => '$(INST_LIBDIR)/RR/NSEC.pm',
		'RR/NSEC3.pm'	   => '$(INST_LIBDIR)/RR/NSEC3.pm',
		'RR/NSEC3PARAM.pm' => '$(INST_LIBDIR)/RR/NSEC3PARAM.pm',
		'RR/RRSIG.pm'	   => '$(INST_LIBDIR)/RR/RRSIG.pm',
		'RR/SIG.pm'	   => '$(INST_LIBDIR)/RR/SIG.pm',
		},

	clean => {FILES => "*~ t/keyset-*"}

	);


sub MY::libscan {
	my $path = $_[1];
	return '' if $path =~ /\B\.svn\b/;
	return $path;
}
