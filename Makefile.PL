#
# $Id: Makefile.PL,v 1.7 2002/06/17 14:36:55 olaf Exp $
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
      'VERSION' => 0.05,
      'PREREQ_PM'             => {
	Net::DNS                  => 0.21,
	Crypt::OpenSSL::RSA       => 0.13,
	Crypt::DSA                => 0.12,
	Math::Pari                => 2.001804,
	File::Basename            => 0.0,
	MIME::Base64              => 0.0,
      },
      'ABSTRACT'                  => 'DNSSEC extensions to Net::DNS',
      'AUTHOR'                    => 'Olaf M. Kolkman <net-dns-sec@ripe.net>',
      'PM' => { 
		'RR/DS.pm' => '$(INST_LIBDIR)/RR/DS.pm',
		'RR/NXT.pm' => '$(INST_LIBDIR)/RR/NXT.pm',
		'RR/KEY.pm' => '$(INST_LIBDIR)/RR/KEY.pm',
		'RR/SIG.pm' =>  '$(INST_LIBDIR)/RR/SIG.pm',
	    },

       clean =>           {FILES => "*~ "}

);

