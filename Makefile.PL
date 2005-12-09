#
# $Id: Makefile.PL 527 2005-12-09 10:51:06Z olaf $
#




warn <<AMEN if $] < 5.008;

Net::DNS has been tested with perl  5.008

The author is confident that this package will work with version
versions 5.6 but not confident that any version below perl 5.6 will
work.

The latest version of perl can always be found at:
                 http://www.cpan.org/src/latest.tar.gz
AMEN

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
      'NAME'	=> 'Net::DNS::SEC',
      'VERSION_FROM'	=> 'SEC.pm',
      'PREREQ_PM'             => {
	Net::DNS                  => 0.44,
	Test::More                => 0.47,
	Crypt::OpenSSL::RSA       => 0.19,
	Crypt::OpenSSL::Bignum    => 0.03,
        Crypt::OpenSSL::DSA       => 0.10,
	Digest::SHA               => 5.23,
	File::Basename            => 0.0,
	MIME::Base64              => 0.0,
	Math::BigInt              => 0.0,
	Time::Local               => 0.0,
	Digest::BubbleBabble      => 0.01,
	Digest::SHA1              => 0.0,
      },
      'ABSTRACT'                  => 'DNSSEC extensions to Net::DNS',
      'AUTHOR'                    => 'Olaf M. Kolkman <olaf@net-dns.org>',
      'PM' => { 
	        'Keyset.pm' => '$(INST_LIBDIR)/Keyset.pm',
		'SEC.pm'    => '$(INST_LIBDIR)/SEC.pm',
		'SEC/Private.pm'    => '$(INST_LIBDIR)/SEC/Private.pm',
		'RR/DS.pm'  => '$(INST_LIBDIR)/RR/DS.pm',
		'RR/NXT.pm' => '$(INST_LIBDIR)/RR/NXT.pm',
		'RR/KEY.pm' => '$(INST_LIBDIR)/RR/KEY.pm',
		'RR/SIG.pm' =>  '$(INST_LIBDIR)/RR/SIG.pm',
		'RR/RRSIG.pm' =>  '$(INST_LIBDIR)/RR/RRSIG.pm',
		'RR/DNSKEY.pm' =>  '$(INST_LIBDIR)/RR/DNSKEY.pm',
		'RR/NSEC.pm' =>  '$(INST_LIBDIR)/RR/NSEC.pm',
	    },

       clean =>           {FILES => "*~ keyset-*"}

);



sub MY::libscan {
    my $path = $_[1];
    return '' if $path =~ /\B\.svn\b/;
    return $path;
}
