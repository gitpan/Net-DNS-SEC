#
# $Id: Makefile.PL,v 1.16 2003/01/09 06:53:46 olaf Exp $
#

eval { require 5.00503  };

die <<SHUCKS if $@;
Net::DNS has been tested with perl 5.00503 and 5.6.1.

The latest version of perl can always be found at:
    
                 http://www.cpan.org/src/latest.tar.gz
SHUCKS

use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
      'NAME'	=> 'Net::DNS::SEC',
      'VERSION_FROM'	=> 'SEC.pm',
      'PREREQ_PM'             => {
	Net::DNS                  => 0.32,
	Test::More                => 0.47,
	Crypt::OpenSSL::RSA       => 0.17,
	Crypt::OpenSSL::DSA       => 0.10,
	File::Basename            => 0.0,
	MIME::Base64              => 0.0,
	Math::BigInt              => 0.0,
	Time::Local               => 0.0,
	Digest::BubbleBabble      => 0.01,
      },
      'ABSTRACT'                  => 'DNSSEC extensions to Net::DNS',
      'AUTHOR'                    => 'Olaf M. Kolkman <net-dns-sec@ripe.net>',
      'PM' => { 
	        'Keyset.pm' => '$(INST_LIBDIR)/Keyset.pm',
		'SEC.pm'    => '$(INST_LIBDIR)/SEC.pm',
		'RR/SIG/Private.pm'    => '$(INST_LIBDIR)/RR/SIG/Private.pm',
		'RR/DS.pm'  => '$(INST_LIBDIR)/RR/DS.pm',
		'RR/NXT.pm' => '$(INST_LIBDIR)/RR/NXT.pm',
		'RR/KEY.pm' => '$(INST_LIBDIR)/RR/KEY.pm',
		'RR/SIG.pm' =>  '$(INST_LIBDIR)/RR/SIG.pm',
	    },

       clean =>           {FILES => "*~ keyset-*"}

);

