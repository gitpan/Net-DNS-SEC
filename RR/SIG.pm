# perldoc SIG.pm for documentation.
# Specs: RFC 2535 section 4
# $Id: SIG.pm,v 1.6 2002/08/14 13:44:53 olaf Exp $

package Net::DNS::RR::SIG;



use strict;
use vars qw(@ISA $VERSION);
use Net::DNS;
use Carp;
use File::Basename;
use MIME::Base64;
use Math::Pari;      #DSA relies on this.


 $VERSION = do { my @r=(q$Revision: 1.6 $=~/\d+/g); sprintf "%d."."%03d"x$#r,@r };



my $debug=0;


#
# The DSA implementation relies on Math::Pari objects. These are helper
# functions we need to deal with DSA
# These functions translate a Math Pari object into a binary string.
# and vice verse
# bin2mp is avialable in Crypt::DSA::Util but we use a local copy intead
# These function where copied from Net::SSH::Perl::Util

sub bin2mp {
    my $s = shift;
    my $p = PARI(0);
    for my $b (split //, $s) {
        $p = $p * 256 + ord $b;
    }
    $p;
}


sub mp2bin {
    my($p, $l) = @_;
    $l ||= 0;
    my $base = PARI(256);
    my $res = '';
    {
        my $r = $p % $base;
        my $d = PARI($p-$r) / $base;
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




#   Ans1 is needed for conversion to X509 style representation of the
#   key material.  see
#   http://www.darmstadt.gmd.de/secude/Doc/htm/pkcs/layman.htm for the
#   # relevant pieces of ANS.1


sub ANS1_integer{
    my $integer=shift;

    # Note: $integer is a binary representation of an unsigned
    # arebritrary length integer....

    #   An integer in ANS.1. is represented by 
    #   0x02 type
    #       Length octets
    #       Data octets

    $integer = pack("C",0) . $integer  if (unpack("C",$integer) & 0x80);
    my $integerlength=length $integer;
    if ($integerlength>127){
	my $a = PARI $integerlength;
	my $binlength = Net::DNS::RR::SIG::mp2bin($a);
	
	$integer= pack("C",0x02).pack("C",length($binlength) | 0x80 ).$binlength .$integer;
    }else{
	$integer= pack("C",0x02).pack("C",$integerlength).$integer;  
    }
    return $integer;

}



sub ANS1_sequence{
    # Helper function to convert a sequence of bits to an ANS1 sequence.
    my $sequence=shift;
    my $sequencelength=length $sequence;
    # secuence: 0x16 with bit 6 set  so type 0x30 followed by length.
    if ($sequencelength>127){
	my $a = PARI $sequencelength;
	my $binlength = Net::DNS::RR::SIG::mp2bin($a);
	
	$sequence= pack("C",0x30).pack("C",length($binlength) | 0x80 ).$binlength .$sequence;
    }else{
	$sequence= pack("C",0x30).pack("C",$sequencelength).$sequence;  
    }
    return $sequence;
}


@ISA = qw(Net::DNS::RR);

sub new {
    my ($class, $self, $data, $offset) = @_;

    if ($self->{"rdlength"} > 0) {
	#RFC2535 section 4.1
	my $offsettoalg=$offset+2;
	my $offsettolabels=$offset+3;
	my $offsettoorgttl=$offset+4;
	my $offsettosigexp=$offset+8;
	my $offsettosiginc=$offset+12;
	my $offsettokeytag=$offset+16;
	my $offsettosignm=$offset+18;

	$self->{"typecovered"}= _type2string(unpack("n",substr($$data,$offset,2)));
	$self->{"algorithm"}=unpack("C",substr($$data,$offsettoalg,1));
	$self->{"labels"}=lc(unpack("C",substr($$data,$offsettolabels,1)));
	$self->{"orgttl"}=unpack("N",substr($$data,$offsettoorgttl,4));
	my @expt=gmtime(unpack("N",substr($$data,$offsettosigexp,4)));
	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $expt[5]+1900 ,$expt[4]+1 , 
					   $expt[3] ,$expt[2] , $expt[1]  , 
					   $expt[0]);
	my @inct=gmtime(unpack("N",substr($$data,$offsettosiginc,4)));
	$self->{"siginceptation"}=  sprintf ("%d%02d%02d%02d%02d%02d",
					     $inct[5]+1900 ,$inct[4]+1 , 
					     $inct[3] ,$inct[2] , $inct[1]  ,
					     $inct[0]);
	$self->{"keytag"}=unpack("n",substr($$data,$offsettokeytag,2));
	my($signame,$sigoffset) = Net::DNS::Packet::dn_expand
	    ($data, $offsettosignm);
	$self->{"signame"}=lc($signame);
	my($sigmaterial)=substr($$data,$sigoffset,
				($self->{"rdlength"}-$sigoffset+$offset));
	$self->{"sigbin"}=$sigmaterial;
	$self->{"sig"}= encode_base64($sigmaterial);
	$self->{"vrfyerrstr"}="";
	
    }
    return bless $self, $class;
}




sub new_from_string {
    my ($class, $self, $string) = @_;
    if ($string) {
	$string =~ tr/()//d;
	$string =~ s/;.*$//mg;
	$string =~ s/\n//mg;
	my ($typecovered, $algoritm,
	    $labels, $orgttl, $sigexpiration,
	    $siginceptation, $keytag,$signame,$sig) = 
		$string =~ 
		    /^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)/;
	croak (" Invallid SIG RR, check your fomat ") if !$keytag;
	$sig =~ s/\s*//g;
	$self->{"typecovered"}= $typecovered;
	$self->{"algorithm"}= $algoritm;
	$self->{"labels"}= lc($labels);
	$self->{"orgttl"}= $orgttl;
	_checktimeformat($sigexpiration);
	_checktimeformat($siginceptation);
	$self->{"sigexpiration"}=  $sigexpiration;
	$self->{"siginceptation"}= $siginceptation;
	$self->{"keytag"}= $keytag;
	$self->{"signame"}= lc($signame);
	$self->{"sig"}= $sig;
	$self->{"sigbin"}= decode_base64($sig);
	$self->{"vrfyerrstr"}="";
    }
    return bless $self, $class;
}


sub rdatastr {
	my $self = shift;
	my $rdatastr;
	if (exists $self->{"typecovered"}) {
	    $rdatastr  = $self->{typecovered};
	    $rdatastr .= "  "  . "$self->{algorithm}";
	    $rdatastr .= "  "  . "$self->{labels}";
	    $rdatastr .= "  "  . "$self->{orgttl}";
	    $rdatastr .= "  "  . "$self->{sigexpiration}";
	    $rdatastr .= " (\n\t\t\t"  . "$self->{siginceptation}";
	    $rdatastr .= " "  . "$self->{keytag}";
	    $rdatastr .= "  "  . "$self->{signame}";
	    # do some nice formatting
	    my $sigstring=$self->{sig};
	    $sigstring =~ s/\n//g;
	    $sigstring =~ s/(\S{45})/$1\n\t\t\t/g;
	    $rdatastr .=  "\n\t\t\t".$sigstring;
	    $rdatastr .= " )";
	    }
	else {
	    $rdatastr = "; no data";
	}

	return $rdatastr;
}


sub rr_rdata_without_sigbin {
    my ($self) = shift;
    my $rdata = "";

    if (exists $self->{"typecovered"}) {
	$rdata  = pack("n",_string2type($self->{typecovered}));
	$rdata .= pack("C",$self->{algorithm});
	$rdata .= pack("C",$self->{"labels"});
	$rdata .= pack("N",$self->{"orgttl"});
	use Time::Local;
	$self->{"sigexpiration"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));

	$self->{"siginceptation"} =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	$rdata .= pack("N",timegm ($6, $5, $4, $3, $2-1, $1-1900));
	$rdata .= pack("n",$self->{"keytag"});
	# Since we will need canonical and expanded names while checking 
	# we do not use the packet->dn_comp here but use RFC1035 p10.
	{   my @dname= split /\./,lc($self->{"signame"});
	    for (my $i=0;$i<@dname;$i++){
		$rdata .= pack ("C",length $dname[$i] );
		$rdata .= $dname[$i] ;

	    }
	    $rdata .= pack ("C","0");
	}
    }
    return $rdata;

}


sub rr_rdata {
    my ($self, $packet, $offset) = @_;
    my $rdata = "";
    if (exists $self->{"typecovered"}) {
	$rdata=$self->rr_rdata_without_sigbin;

	if ($self->{"sig"} ne "NOTYETCALCULATED") {
            $rdata .= $self->{"sigbin"};
	}else{
            #do sigzero calculation based on current packet content...
	    
	    die "Signature not known for a not SIG0 type of signature" if ($self->{"typecovered"} ne "SIGZERO");
	    die "Private key not known for SIG0" if (! exists $self->{"private_key"});
	    

	    my $rr=$packet->pop("additional");
	    die "SIG0 should be the last RR in the packet" if ($rr->type ne "SIG");
	    die "Unexpected error during creation of SIG0. " if ($rr ne $self);
	    print "Processing SIG0 signature\n" if $debug;

	    my $data;
	    # Compress the data and make sure we will not go into deep
	    # recursion 
	    if ($self->{"rr_rdata_recursion"}==0){	    
		$self->{"rr_rdata_recursion"}=1;	    

		$data=$packet->data;

		my $sigdata=$self->_CreateSigData($data);
		my $signature;

		if ($self->{"algorithm"} == 1 ||
		    $self->{"algorithm"} == 5)
		{  #RSA
		    my $rsa_priv = Crypt::OpenSSL::RSA->new();
		    eval {
			$rsa_priv->use_pkcs1_oaep_padding;
			if ($self->{"algorithm"} == 1) {
			    $rsa_priv->use_md5_hash;
			} else {
			    $rsa_priv->use_sha1_hash;
			}
			$rsa_priv->load_private_key($self->{"private_key"});
		    };
		    die "Error loading RSA private key " . $@ if $@;

		    eval {
			$signature = $rsa_priv->sign($sigdata);
		    };
		    die "RSA Signature generation failed ".$@ if $@;

		    print "\n SIGNED" if $debug ;
		    
		}elsif ($self->{"algorithm"} == 3){  #DSA
		    use Crypt::DSA::Key;
		    use Crypt::DSA;
		    my $dsa = Crypt::DSA->new;

		    my $prikey = $self->{"private_key"};


		    # If $sigzero then we want to sign data if given
		    # in the argument. If the argument is empty we
		    # sign when the packet put on the wire.

		    if (my $sig= $dsa->sign(
					    Message    => $sigdata,
					    Key        => $prikey,
					    ))
		    {
			print "\n SIGNED" if $debug ;

			# See RFC 2535 for the content of the SIG and
			# see Crypt::DSA::Signature for the methods to
			# access the data.


			my $base_g=$self->{"private_key"}->{"base_g"};
			my $T_parameter= (length(decode_base64($base_g))-64)/8;
			$signature=pack("C",$T_parameter);
			$signature.=Net::DNS::RR::SIG::mp2bin($sig->r);
			$signature.=Net::DNS::RR::SIG::mp2bin($sig->s);
		    }else
		    {  
			confess "creation of DSA Signature failed " ;
		    }
		}
		
		
		
		$self->{"sigbin"}=$signature;
		$self->{"sig"}= encode_base64($signature);
		$rdata .= $self->{"sigbin"};
	    }
	    $packet->push("additional", $self);
	}
    }
    return $rdata;
    
}

sub create {
    my ($class,  $datarrset, $key_file, %args) = @_;

    # This method returns a sigrr with the signature over the
    # datatrrset (an array of RRs) made with the private key stored in
    # the $key_file.

    my $self;
    $self->{"sigerrstr"}="---- Unknown Error Condition ------";


    # if $datarrset is a plain datastrream then construct a sigzero sig.
    # So any number will actually do.

    my $sigzero= ! ref ($datarrset);
    $self->{"rr_rdata_recursion"}=0;

    # Start with seting up the data in the packet we can get our hands on...

    if ($sigzero){
	$self->{"name"}="";
    }else{
	$self->{"name"}=$datarrset->[0]->name;
    }

    $self->{"type"}="SIG";
    $self->{"class"}="IN";


    if ($sigzero){
	# RFC 2931 sect 3
	$self->{"ttl"}=0;
	$self->{"class"}="any";
    }elsif ($args{ttl}){
	print "\nSetting TTL to ".  $args{"ttl"} if $debug;
	$self->{"ttl"}= $args{"ttl"};
    }else{
	$self->{"ttl"}= 3600;
    }

    if ($sigzero){
	$self->{"typecovered"}="SIGZERO";
    }else{
	$self->{"typecovered"}=$datarrset->[0]->type;  #Sanity checks elsewhere
    }


    if ($args{response}){
	$self->{"response"}=$args{"response"};
    }

    if ($args{"sigin"}){
	_checktimeformat($args{"sigin"});
	print "\nSetting siginceptation to " . $args{"sigin"} if $debug;
	$self->{"siginceptation"} =$args{"sigin"};
    }else{
	my @inct=gmtime(time);
	my $currentdatestring=  sprintf ("%d%02d%02d%02d%02d%02d",
					 $inct[5]+1900 ,$inct[4]+1 , 
					 $inct[3] ,$inct[2] , $inct[1]  ,
					 $inct[0]);	
	$self->{"siginceptation"} = $currentdatestring ;
    }

    # This will fail if the dateformat is not correct...
    $self->{"siginceptation"} =~ 
	/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/ ;
    my $siginc_time=timegm ($6, $5, $4, $3, $2-1, $1-1900);

    if ($args{"sigval"}){ #sigexpiration set by siginception + sigval
	my @inct;


	if ($sigzero){
	    # treat sigval as minutes
	    @inct=gmtime($siginc_time+$args{"sigval"}*60 );  
	}else{
	    # treat sigval as days
	    @inct=gmtime($siginc_time+$args{"sigval"}*24*3600 );  
	}
	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $inct[5]+1900 ,$inct[4]+1 , 
					   $inct[3] ,$inct[2] , $inct[1]  ,
					   $inct[0]);	
    }elsif ($args{"sigex"}) { #sigexpiration set by the argument
	_checktimeformat($args{"sigex"});
	if ( $self->{"siginceptation"} > $args{"sigex"} ){
	    croak "Signature can only expire after it has been incepted (".
		$args{"sigex"} . "<" . $self->{"siginceptation"} .
		    ")";
	}
	print "\nSetting sigexpiration to " . $args{"sigexp"} if $debug;
	$self->{"sigexpiration"}=$args{"sigex"} ;
    }else{ 
	my @inct;
	if ($sigzero){
	    #default 5 minutes
	    @inct=gmtime($siginc_time+5*60  );  
	}else{
	   # Take the 30 days default for sigexpiration 	
	    @inct=gmtime($siginc_time+30*24*3600 );  
	}
	$self->{"sigexpiration"}= sprintf ("%d%02d%02d%02d%02d%02d",
					   $inct[5]+1900 ,$inct[4]+1 , 
					   $inct[3] ,$inct[2] , $inct[1]  ,
					   $inct[0]);	
    }
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

    if (!$sigzero)    {   
	my  $labels=$datarrset->[0]->name;
	$labels =~ s/\.^//;  # remove trailing dot.
	my @labels= split /\./ , $labels;
	$self->{"labels"}= scalar(@labels);
	
    }else{
	$self->{"labels"}= 0;
    }

    # All the TTLs need to be the same in the data RRset.
    if ( (!$sigzero) && @{$datarrset}>1){
	for (my $i=0; $i<@{$datarrset}; $i++){
	    if ($datarrset->[0]->{"ttl"} != $datarrset->[$i]->{"ttl"}){
		croak "\nNot all TTLs  in the data RRset are equal ";
	    }
	}
    }
  
    if ($sigzero){
	$self->{"orgttl"}=0;
    }else{	
	$self->{"orgttl"}=$datarrset->[0]->{"ttl"};  
    }


    $self->{"sig"}=  "NOTYETCALCULATED";  # This is what we'll do in a bit...
    $self->{"sigbin"}= decode_base64($self->{"sig"});

    # Bless the whole thing so we can get access to the methods...
    # (Don not ask me why I havent called the new method, There are
    # more ways to do things)

    bless $self, $class;
    
    my $sigdata=$self->_CreateSigData($datarrset);


    # We will now create a Crypt::OpenSSL::RSA object. It is needed
    # for signing.  
    # The Crypt::OpenSSL::RSA class uses ANS1 DER encoding to read private
    # and public keys.


    my    ($Modulus,$PublicExponent,$PrivateExponent,$Prime1,
	   $Prime2,$Exponent1,$Exponent2,$Coefficient,
	   $prime_p,$subprime_q,$base_g,$private_val_x,$public_val_y);
    
    my $signature;
    
    
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
	    $Modulus=ANS1_integer(decode_base64($1));
	} elsif (/^PublicExponent:\s*(\S+)/) {
	    $PublicExponent=ANS1_integer(decode_base64($1));
	} elsif (/^PrivateExponent:\s*(\S+)/) {
	    $PrivateExponent=ANS1_integer(decode_base64($1));
	} elsif (/^Prime1:\s*(\S+)/) {
	    $Prime1=ANS1_integer(decode_base64($1));
	} elsif (/^Prime2:\s*(\S+)/) {
	    $Prime2=ANS1_integer(decode_base64($1));
	} elsif (/^Exponent1:\s*(\S+)/) {
	    $Exponent1=ANS1_integer(decode_base64($1));
	} elsif (/^Exponent2:\s*(\S+)/) {
	    $Exponent2=ANS1_integer(decode_base64($1));
	} elsif (/^Coefficient:\s*(\S+)/) {
	    $Coefficient=ANS1_integer(decode_base64($1));
	} elsif (/^Prime\(p\):\s*(\S+)/) {				#RSA
	    $prime_p=$1;
	} elsif (/^Subprime\(q\):\s*(\S+)/) {
	    $subprime_q=$1;
	} elsif (/^Base\(g\):\s*(\S+)/) {
	    $base_g=$1;
	} elsif (/^Private_value\(x\):\s*(\S+)/) {
	    $private_val_x=$1;
	} elsif (/^Public_value\(y\):\s*(\S+)/) { 
	    $public_val_y=$1;
	}
    }
    close(KEYFH);
    
    #
    # Enjoy the crypto
    if ($self->{"algorithm"} == 1 || $self->{"algorithm"} == 5) {  #RSA
	use Crypt::OpenSSL::RSA;
	

	my $Version=ANS1_integer(pack("C",0));
	my $RSAPrivateKey="-----BEGIN RSA PRIVATE KEY-----\n".
	    encode_base64(
			  ANS1_sequence(
					$Version .
					$Modulus.
					$PublicExponent.
					$PrivateExponent.
					$Prime1.
					$Prime2.
					$Exponent1.
					$Exponent2.
					$Coefficient
					)
			  )
		."-----END RSA PRIVATE KEY-----";
	
	my $rsa_priv = Crypt::OpenSSL::RSA->new();
	$self->{"private_key"}=$RSAPrivateKey;
	eval {
	    $rsa_priv->use_pkcs1_oaep_padding;
	    if ($self->{"algorithm"} == 1) {
		$rsa_priv->use_md5_hash;
	    } else {
		$rsa_priv->use_sha1_hash;
	    }
	    $rsa_priv->load_private_key($RSAPrivateKey);
	};
	die "RSA private key loading failed:".$@ if $@;
	eval {
	    $signature = $rsa_priv->sign($sigdata);
	};
	die "RSA Signature generation failed ".$@ if $@;

	print "\n SIGNED" if $debug ;
	
    }elsif ($self->{"algorithm"} == 3){  #DSA
	use Crypt::DSA::Key;
	use Crypt::DSA;
	my $dsa = Crypt::DSA->new;
	my $prikey = Crypt::DSA::Key->new;
	#See perldoc Crypt::DSA::Key for the methods below
	$prikey->p(&Net::DNS::RR::SIG::bin2mp(decode_base64($prime_p)));
	$prikey->q(&Net::DNS::RR::SIG::bin2mp(decode_base64($subprime_q)));
	$prikey->g(&Net::DNS::RR::SIG::bin2mp(decode_base64($base_g)));
	$prikey->priv_key(&Net::DNS::RR::SIG::bin2mp(decode_base64($private_val_x)));
	$prikey->pub_key(&Net::DNS::RR::SIG::bin2mp(decode_base64($public_val_y)));


	$self->{"private_key"}=$prikey;
	$self->{"private_key"}->{"base_g"}=$base_g;

	# If $sigzero then we want to sign data if given in the
	# argument. If the argument is empty we sign when the packet
	# put on the wire.

	if ($datarrset ne "" ){
	    if (my $sig= $dsa->sign(
				    Message    => $sigdata,
				    Key        => $prikey,
				    ))
	    {
		print "\n SIGNED" if $debug ;
		# See RFC 2535 for the content of the SIG and see 
		# Crypt::DSA::Signature  for the methods to access the data.
		my $T_parameter= (length(decode_base64($base_g))-64)/8;
		$signature=pack("C",$T_parameter);
		$signature.=Net::DNS::RR::SIG::mp2bin($sig->r);
		$signature.=Net::DNS::RR::SIG::mp2bin($sig->s);
	    }else
	    {  
		confess "creation of DSA Signature failed " ;
	    }
	}
	    
    }


    if ($datarrset ne "" ){
	# Replace the "sig" by the real signature and return the object.
	$self->{"sigbin"}=$signature;
	$self->{"sig"}= encode_base64($signature);
    }

    return $self;
}


sub verify {
    my ($self, $dataref, $keyrr) = @_;

    # Reminder...

    # $dataref may be a reference to an array of RR objects:
    # $dataref->[$i]->method is the call to the method of the $i th
    # object in the array...  @{$dataref} is length of the array when
    # called in numerical context

    # Alternatively %dataref may refer to a a Net::DNS::Packet.

    # if $dataref is not a reference it contains a string with data to be 
    # verified using SIG0
    
    my $sigzero_verify=0;
    my $packet_verify=0;
    my $rrarray_verify=0;
   
    print "Verifying data of class:".  ref( $dataref) . "\n" if $debug;
    $sigzero_verify=1 unless (ref($dataref));
    if (! $sigzero_verify ){
	if (ref($dataref) eq "ARRAY"){

	    if (ref($dataref->[0]) and $dataref->[0]->isa('Net::DNS::RR')){
		$rrarray_verify=1;
	    }else{
		die "Trying to verify an array of ".  ref( $dataref->[0]) ."\n";
	    }
	}elsif( (ref($dataref)) and $dataref->isa("Net::DNS::Packet")){
	    $packet_verify=1 if ((ref($dataref)) and $dataref->isa("Net::DNS::Packet"));
	    die "Trying to verify a packet while signature is not of SIG0 type"
		if ($self->{"typecovered"} ne "SIGZERO");
	    
	}else{
	    die "Do not know what kind of data this is" . ref( $dataref) . ")\n";
	}
    }

    $self->{"vrfyerrstr"}="---- Unknown Error Condition ------";
    print "\n ------------------------------- SIG DEBUG  -----------------\n"  if $debug;
    print "Reference: ".ref($dataref) if $debug;;
    print "\n  SIG:\t", $self->string if $debug;
    if ( $rrarray_verify ){
	for (my $i=0; $i<@{$dataref}; $i++){
	    print "\n DATA:\t", $dataref->[$i]->string if $debug ;
	}
    }
    print "\n  KEY:\t" , $keyrr->string if $debug;
    print "\n ------------------------------------------------------------\n" if $debug;



     
    if (!$sigzero_verify && !$packet_verify && $dataref->[0]->type ne $self->typecovered ) {
	$self->{"vrfyerrstr"} = "\nCannot verify datatype  " . $self->typecovered . 
	    " with a key intended for " . 
		$dataref->[0]->type .
		    " verification\n";
	return 0;
    }


    if ( $rrarray_verify &&  !$dataref->[0]->type eq "SIG" ) {
	# if [0] has type SIG the whole RRset is type SIG. 
	# There are no SIGs over SIG RRsets
	$self->{"vrfyerrstr"} = 
	    "SIGs over SIGs???\n" .
 	   " What are you trying to do. This is not possible.\n";
	return 0;
    }
    if ( $self->algorithm != $keyrr->algorithm ){
	$self->{"vrfyerrstr"} = 
	    "It is impossible to verify a signature made with algorithm " .
		$self->algorithm . "\nagainst a key made with algorithm " .
		    $keyrr->algorithm . "\n";
	return 0;

    }

    if ( $packet_verify){
	# We keep the intelligence for verification in here....
	# The packet is compressed ... we have to undo the compression.
	# Do this by creating a newpaclet
	my $newpacket;
	bless($newpacket = {},"Net::DNS::Packet");
	%{$newpacket} = %{$dataref};
	bless($newpacket->{"header"} = {},"Net::DNS::Header");
	%{$newpacket->{"header"}} = %{$dataref->{"header"}};
	@{$newpacket->{"additional"}} = @{$dataref->{"additional"}};
	shift(@{$newpacket->{"additional"}});
	$newpacket->{"header"}{"arcount"}--;
	$newpacket->{"compnames"} = {};
	$dataref=$dataref->data;
    }


    # The data that is to be signed
    my $sigdata=$self->_CreateSigData($dataref);
    my $signature=$self->sigbin; 
    my $verified=0;
    if ( $self->algorithm == 1 ){    #Verifying for RSA
	$verified=$self->_verifyRSA($sigdata,$signature,$keyrr,0) || return 0;
    }     
    elsif ( $self->algorithm == 3 )  # Verifying for DSA
    {
	 $verified=$self->_verifyDSA($sigdata,$signature,$keyrr) || return 0;
    }
    elsif ( $self->algorithm == 5 )  # Verifying for RSASHA1
    {
	$verified=$self->_verifyRSA($sigdata,$signature,$keyrr,1) || return 0;
    }
    else                                  # Verifying other algorithms
    { 
	$self->{"vrfyerrstr"}= "Algoritm ". $self->algorithm . " has not yet been implemented";
	return 0;
    }	
    
    # This really is a redundant test
    if ($verified) {  
        # time to do some time checking.
	my @inct=gmtime(time);
	my $currentdatestring=  sprintf ("%d%02d%02d%02d%02d%02d",
					     $inct[5]+1900 ,$inct[4]+1 , 
					     $inct[3] ,$inct[2] , $inct[1]  ,
					     $inct[0]);	
	if ($self->{"siginceptation"} > $currentdatestring ){
	    $self->{"vrfyerrstr"}= "Signature may only be used in the future; after " .
		$self->{"siginceptation"} ;
	    return 0;
	}elsif($self->{"sigexpiration"} < $currentdatestring ){
	    $self->{"vrfyerrstr"}= "Signature has expired since: " .
		$self->{"sigexpiration"} ;
	    return 0;
	}
	$self->{"vrfyerrstr"}= "No Error";
	return 1;
    }
    
    $self->{"vrfyerrstr"}="Verification method error.";
    return 0;

} #END verify block




# Below are all sorts of helper functions. 
# They should not really be used outside the scope of this class ...
#
# To do:  make these functions invisable outside the class.
#
sub _type2string {
    my $index=shift;
    if( exists $Net::DNS::typesbyval{$index}){
	return $Net::DNS::typesbyval{$index} ;
    }else{
	return "UNKNOWN TYPE";
    }
}

sub _string2type {
    my $index=shift;
        if( exists $Net::DNS::typesbyname{uc($index)}){
	return $Net::DNS::typesbyname{uc($index)} ;
    }else{
	carp "UNKNOWN QTYPE, cannot continue ";
    }
}






sub _verifyDSA {
    my ($self, $sigdata, $signature, $keyrr) = @_; 

    print "\nDSA verification called with key:\n". $keyrr->string . 
	
	" and sig:\n" . $self->string ."\n" if $debug;
    # RSA RFC2536
    #
    # Setup a DSA::Key. 
    #
    use Crypt::DSA;

    # first extract variables from the keymaterial (RFC2535 section2)
    # Also read FIPS PUB 186 (Federal Information Processing Standards Publication 186
    # 
    # Public Key Elements
    my $T_field_key=&Net::DNS::RR::SIG::bin2mp(substr($keyrr->keybin,
						 0,
						 1));
    my $Q_field=&Net::DNS::RR::SIG::bin2mp(substr($keyrr->keybin, 
						 1,
						 20));
    my $P_field=&Net::DNS::RR::SIG::bin2mp(substr($keyrr->keybin, 
						 21, 
						 64+$T_field_key*8)) ;
    my $G_field=&Net::DNS::RR::SIG::bin2mp(substr($keyrr->keybin, 
						 21+64+$T_field_key*8,
						 64+$T_field_key*8));
    my $Y_field=&Net::DNS::RR::SIG::bin2mp(substr($keyrr->keybin, 
						 21+2*(64+$T_field_key*8),
						 64+$T_field_key*8)) ;
    
    if ( $debug ) {
	print "\n\n------------Studying DSA key content.-----------------".
	    "\n KEY MAT=". unpack("H*",$keyrr->keybin);
	print "\n T_field=". unpack("H*",substr($keyrr->keybin,
						0,						1));
	print "\n T_field=". $T_field_key;
	print "\n Q_field=". unpack("H*",substr($keyrr->keybin, 
						1,
						20));
	print "\n Q_field=". $Q_field;
	print "\n P_field=". unpack("H*",,substr($keyrr->keybin, 
						 21, 
						 64+$T_field_key*8)) ;
	print "\n P_field=". $P_field;
	print "\n G_field=". unpack("H*",substr($keyrr->keybin, 
						21+64+$T_field_key*8,
						64+$T_field_key*8));
	print "\n G_field=". $G_field;
	print "\n Y_field=". unpack("H*",substr($keyrr->keybin, 
						21+2*(64+$T_field_key*8),
						64+$T_field_key*8)) ;
	print "\n Y_field=". $Y_field;
	print "\n-----------------------------\n";
    }
    
    my $dsa= new Crypt::DSA;
    my $dsakey= new Crypt::DSA::Key;
    
    $dsakey->p($P_field);       # See FIPS186 section 4
    $dsakey->g($G_field);
    $dsakey->q($Q_field);
    $dsakey->pub_key($Y_field); 

    # Signature elements.  (See RFC2536 section 3 and FIPS186 section 5)
    
    my $T_field_sig=&Net::DNS::RR::SIG::bin2mp(substr($self->sigbin,
						 0,
						 1));
    my $R_field=&Net::DNS::RR::SIG::bin2mp(substr($self->sigbin,
						 1,
						 20));
    my $S_field=&Net::DNS::RR::SIG::bin2mp(substr($self->sigbin,
						 21,
						 20));

    if ( $debug ) {
	print "\n\n------------Studying DSA sig content.-----------------".
	    "\n SIG MAT=". unpack("H*",$self->sigbin);
	print "\n T_field=". unpack("H*",substr($self->sigbin,
						0,
						1));
	print "\n T_field=". $T_field_sig;
	print "\n R_field=". unpack("H*",substr($self->sigbin, 
						1,
						20));
	print "\n R_field=". $R_field;
	print "\n S_field=". unpack("H*",,substr($self->sigbin, 
						 21, 
						 20)) ;
	print "\n S_field=". $S_field;
	print "\n-----------------------------\n";
    }
    
    my $dsasig= new Crypt::DSA::Signature;
    $dsasig->r($R_field);
    $dsasig->s($S_field);

    if ( $dsa->verify ( 
			Message => $sigdata,
			Signature => $dsasig,
			Key => $dsakey,
			)){
	$self->{"vrfyerrstr"}="DSA Verification successful ";
	return(1);
    }else{
	$self->{"vrfyerrstr"}="DSA Verification failed ";
    }
    
    $self->{"vrfyerrstr"}="DSA Verification failed: undefined error ";
    
    return 0;
}



sub _verifyRSA {
    # Implementation using crypt::openssl

    my ($self, $sigdata, $signature, $keyrr, $isSHA) = @_; 

    print "\nRSA verification called with key:\n". $keyrr->string . 
	
	" sig:\n" . $self->string ."\non sigdata:\t".
	    unpack ("H*",$sigdata) . "\n" 
	    if $debug;
    # RSA RFC2535
    # 
    # Again we need to put the public key into ANS1 DER encoding so that
    # the RSA public key can read it.
    use Crypt::OpenSSL::RSA;

    my $rsa_pub = Crypt::OpenSSL::RSA->new();
    $rsa_pub->use_pkcs1_oaep_padding;
    if ($isSHA) {
	$rsa_pub->use_sha1_hash;
    } else {
	$rsa_pub->use_md5_hash;
    }
    
    my $explength;
    my $exponent;
    my $modulus;
    my $RSAPublicKey;
	
    {   #localise dummy
	my $dummy=1;
	# determine exponent length
	
	#RFC 2537 sect 2
	($dummy, $explength)=unpack("Cn",$keyrr->keybin) 
	    if ! ($explength=unpack("C",$keyrr->keybin));
	print "\n\nEXPLENGTH:",$explength if $debug;
	
	# We are constructing the exponent and modulus as a hex number so 
	# the AUTOLOAD function in Crypt::RSA::Key::Public can deal with it
	# later, there must be better ways to do this,
	if ($dummy) { # skip one octet
	    $exponent=(substr ($keyrr->keybin, 
			       1, 
			       $explength));
	    
	    $modulus=( substr ($keyrr->keybin,
			       1+$explength, 
			       (length $keyrr->keybin) - 1
			       - $explength));
	    
	    
	}else{ # skip two octets
	    $exponent=(substr ($keyrr->keybin, 
			       3,
			       $explength));
	    
	    $modulus=( substr ($keyrr->keybin, 
			       3+$explength, 
			       (length $keyrr->keybin) - 3
			       - $explength));
	}
    }
    
    
    #   We have the modulus and the exponent we now need to put this
    #   in an X509 encoded public key to use
    #   Crypt::OpenSSL::RSA::load_public_key 
    
    
    #   Load a public key in from an X509 encoded string. The string
    #   should include the -----BEGIN...----- and -----END...-----
    #   lines. The padding is set to PKCS1_OAEP, but can be changed
    #   with set_padding.
    
    #   the modulus is a multiprecicion unsigned integer.  
    #   The modulus in the RSA secuence is an integer as well.
    
    # The modulus is an unsigned integer. The ANS.1 DER encoding is two complements form.
    # If the first bit of $modulus is 1 we have to append a 0 octed.


    $modulus=ANS1_integer($modulus);
    $exponent=ANS1_integer($exponent);
    
    # Same for the exponent.
    
    my $sequence=ANS1_sequence($modulus . $exponent);

    
    $RSAPublicKey="-----BEGIN RSA PUBLIC KEY-----\n".
	encode_base64($sequence) .
	    "-----END RSA PUBLIC KEY-----\n";


    eval {
	$rsa_pub->load_public_key($RSAPublicKey);
    };
    die "Could not load public key: " . $@ if $@;

    my $verified;
    eval {
	$verified=$rsa_pub->verify($sigdata, $signature);
    };

    if ($@){
	 $self->{"vrfyerrstr"}=
	     "Verification of RSA string generated error: ". $@;
	 print "\nRSA library error.\n" if $debug;
	 return 0;
     }
    if ($verified )
    {
	print "\nVERIFIED\n\n" if $debug ;
	$self->{"vrfyerrstr"}="RSA Verification successful";
	return 1;
    }else
    {   $self->{"vrfyerrstr"}="RSA Verification failed";
	# Data is not verified
	print "\nNOT VERIFIED\n" if $debug;
	return 0;
    }
    
    $self->{"vrfyerrstr"}="RSA Verification failed: This code should not be run ";
    0;

}

sub _CreateSigData {
    # this is the data that will be  signed, it will be fed to the
    # verifier. See RFC2535 4.1.8 on how this string is constructed

    # This method is called by the method that creates as signature
    # and by the method that verifies the signature. It is assumed
    # that the creation method has checked that all the TTL are the same
    # for the dataref and that sig->orgttl has been set to the TTL of
    # the data. This method will set the datarr->ttl to the sig->orgttl for
    # all the RR in the dataref.



    my ($self,$rawdata)=@_;

    my $sigzero= ! ref ($rawdata);
    my $sigdata;
    # construction of message 


    my $rdatawithoutsig=$self->rr_rdata_without_sigbin;
    print "\n\nstrip:\t\t",  unpack("H*", $rdatawithoutsig) if $debug;
    $sigdata= $rdatawithoutsig;


    if ( ! $sigzero ){  
	# Not a SIG0
	if (@{$rawdata}>1) {
	    my @canonicaldataarray;
	    for (my $i=0; $i<@{$rawdata}; $i++){
		if ($debug){
		    print "Setting TTL to from ". $rawdata->[$i]->{"ttl"} . " to " .
			$self->orgttl . "\n" 
			    if ( $rawdata->[$i]->{"ttl"}!=$self->orgttl);
		}
		$rawdata->[$i]->{"ttl"}=$self->orgttl;
		# Some error checking is done to. A RRset is defined by 
		# Same label,class,qtype
		if ($rawdata->[$i]->name ne $rawdata->[0]->name){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nNot all labels in the data RRset above are equal ";
		}
		
		if ($rawdata->[$i]->type ne $rawdata->[0]->type){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nThe  the data RRset consists of different types ";
		}
		
		if ($rawdata->[$i]->class ne $rawdata->[0]->class){
		    print "\nError:\n";
		    for  (my $j=0; $j<@{$rawdata}; $j++){
			print "\n";
			$rawdata->[$j]->print;
		    }
		    croak "\nThe  the data RRset has different classes (What are you trying to do?)  ";
		}
		
		print "\n\nCan Data RR: $i\t", 
		unpack("H*", ($rawdata->[$i]->_canonicaldata)) if $debug;
		
		# To allow for sorting on RDATA we create an array of hashes.
		# We sort on canonicalRdata and use the full RR representation 
		# in rr to build the digest.
		$canonicaldataarray[$i]= 
		{ rrdigest => $rawdata->[$i]->_canonicaldata,
		  canonicalRdata => $rawdata->[$i]->_canonicalRdata,
	      };
	    }
	    
	    # Sort acording to RFC2535 section 8.3
	    # Comparing left justified octet strings: perl sort does just that.
	    # We have to sort on RDATA.. the array contains the whole RRset.
	    #  the sort routine
	    
	    my @sortedcanonicaldataarray= sort        {
		$a->{"canonicalRdata"} cmp $b->{"canonicalRdata"};   
	    }
	    @canonicaldataarray;
	    
	    
	    
	    for (my $i=0; $i<@sortedcanonicaldataarray ; $i++){
		print "\n>>>" . $i 	.
		    ">>> \t" .
			unpack("H*",$sortedcanonicaldataarray[$i]{canonicalRdata}) .
			    "\n>>>\t " .
				unpack("H*",$sortedcanonicaldataarray[$i]{rrdigest}) .
				    "\n" if $debug;
		$sigdata .=  $sortedcanonicaldataarray[$i]{rrdigest};
	    }
	}else{
	    if ($debug) {
		print "\nSetting TTL to from ". $rawdata->[0]->{"ttl"} . " to " .
		    $self->orgttl . "\n" if 
			( $rawdata->[0]->{"ttl"}!=$self->orgttl );
	    }
	    print "\nRDATA: \t" .$rawdata->[0]->_canonicalRdata ."\t" .
		unpack("H*",$rawdata->[0]->_canonicalRdata) ."\n" if $debug;
	    
	    $rawdata->[0]->{"ttl"}=$self->orgttl;	    
	    $sigdata .= $rawdata->[0]->_canonicaldata;
	    
	}
	
    }else{ #SIG0 case  

	print "\nsig0 proccessing\nrawdata:\t". unpack("H*",$rawdata)."\n"if $debug;
	$sigdata=$sigdata.$rawdata;
    }
    

    print "\n sigdata:\t".   unpack("H*",$sigdata) . "\n" if $debug;

    return $sigdata;
}


sub _checktimeformat {
    # Function to check if the strings entered as time are properly formated.
    # Croaks if the format does not make sense...
    
    
    my $timestring=shift;

    my @timeval=($timestring =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/);
    if (@timeval != 6) {
	croak "The time " . $timestring . " is not in the expected format (yyyymmddhhmmss)";
    }
    if ($timeval[0]< 1970) {
	croak "The year ". $timeval[0] . " is before the epoch (1970)";
    }
    if ($timeval[1]> 12) {
	croak "What??? There is no month number ". $timeval[1] ;
    }
    # This is a rough check... 
    # Feb 31 will work... 
    if ($timeval[2]> 31) {
	croak "Intresting, a month with ". $timeval[2] . " days" ;
    }

    if ($timeval[3]> 24) {
	croak "Intresting, a day with ". $timeval[3] . " hours" ;
    }

    if ($timeval[4]> 60) {
	croak "Intresting, an hour with ". $timeval[3] . " minutes" ;
    }
    if ($timeval[5]> 60) {
	croak "Intresting, a minute with ". $timeval[3] . " seconds" ;
    }

    
    0;
}




1;


=head1 NAME

Net::DNS::RR::SIG - DNS SIG resource record

=head1 SYNOPSIS

C<use Net::DNS::RR>;

=head1 DESCRIPTION


Class for DNS Address (SIG) resource records. In addition to the
regular methods in the Net::DNS::RR the Class contains a method to
sign RRsets using private keys (create). And a class for verifying
signatures over RRsets (verify).

The SIG RR is an implementation of RFC 2535 and RFC 2931.




=head1 METHODS

=head2 create
    
Create a signature over a RR set or over a packet (SIG0).

    my $keypath= 
            "/home/olaf/keys/Kbla.foo.+001+60114.private";
    my $sigrr= create Net::DNS::RR::SIG(\@datarrset,
					$keypath);
    my $sigrr= create Net::DNS::RR::SIG(\@datarrset,
					$keypath,
					\%arguments);
    $sigrr->print;

create is an alternative constructor for a SIG RR object.  

The first argument is either reference to an array that contains the
RRset that needs to be signed or a string containing the data over
wich a SIG0 type of signature needs to be constructed.

The second argument is a string containing the path to a file
containing the the private key as generated with dnssec-keygen, a
program that commes with the bind distribution.

The third argument is an anonymous hash containing the following
possible arguments:  

    ( ttl => 3600,                        # TTL 
      sigin =>   20010501010101,          # signature inceptation 
      sigex =>   20010501010101,          # signature expiration
      sigval => 1.5                       # signature validity
      )

The default for the ttl is 3600 seconds. sigin and sigex need to be
specified in the following format 'yyyymmddhhmmss'. The default for
sigin is the time of signing. 

sigval is the validity of the signature in minutes for SIG0s and days
for other signatures (sigex=sigin+sigval).  If sigval is specified
then sigex is ignored. The default for sigval is 5 minutes for SIG0s
and 30 days other types of signatures.


Note that for SIG0 signatures the default sigin is calculated at the
moment the object is created, not at the moment that the packet is put
on the wire (with ....). So do not leave the object hanging around for
more than a couple of seconds before sending it.

Notes: 

- Do not change the name of the file generated by dnssec-keygen, the
create method uses the filename as generated by dnssec-keygen to determine 
the keyowner, algorithm and the keyid (keytag).

- Only RSA signatures (algorithm 1) and DSA signatures (algorithm 3)
  have been implemented.



=head2 typecovered

    print "typecovered =", $rr->typecovered, "\n"

Returns the qtype covered by the sig.

=head2 algorithm

    print "algorithm =", $rr->algorithm, "\n"

Returns the algorithm number used for the signature

=head2 labels

    print "labels =", $rr->labels, "\n"

Returns the the number of labels of the RRs over wich the 
sig was made.

=head2 orgttl

    print "orgttl =", $rr->orgttl, "\n"

Returns the RRs the original TTL of the signature

=head2 sigexpiration

    print "sigexpiration =", $rr->sigexpiration, "\n"

Returns the expiration date of the signature

=head2 siginceptation

    print "siginceptation =", $rr->siginceptation, "\n"

Returns the date the signature was incepted.

=head2 keytag

    print "keytag =", $rr->keytag, "\n"

Returns the the keytag (key id) of the key the sig was made with.
Read "KeyID Bug in bind." below.

=head2 signame

    print "signame =", $rr->signame, "\n"

Returns the name of the public KEY RRs  this sig was made with.
(Note: the name does not contain a trailing dot.)

=head2 sig

    print "sig =", $rr->sig, "\n"

Returns the base64 representation of the signature.


=head2 verify and vrfyerrstr

    $sigrr->verify($data, $keyrr) || croak $sigrr->vrfyerrstr;


If $data contains a reference to an array of RR objects then them
method verifies the RRset against the signature contained in the
$sigrr object itself using the public key in $keyrr.  Because of the
KeyID bug in bind (see below) a check on keyid is not performed.


If $data contains a reference to a Net::DNS::Packet and if $sig->type
equals zero a a sig0 verification is performed. Note that the
signature needs to be 'popped' from the packet before verifying.


Returns 0 on error and sets $sig->vrfyerrstr

=head2 Example


   my $sigrr=$packet->pop("additional");
   print $sigrr->vrfyerrstr unless $sigrr1->verify($update1, $keyrr1);


=head1 Remarks

- The code is not optimized for speed whatsoever. It is probably not
suitable to be used for signing large zones. 

=head1 TODO

- Clean up the code.

- If this code is still around by 2030 you have a few years to check
the proper handling of times...

- Add wildcard handling


=head1 ACKNOWLEDGMENTS

Andy Vaskys (Network Associates Laboratories) supplied the code for
handling RSA with SHA1 (Algorithm 5).

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
L<Net::DNS::Header>, L<Net::DNS::Question>,
L<Net::DNS::RR>,L<Crypt::OpenSSL::RSA>,L<Crypt::DSA> RFC 2435 Section
4, RFC 2931.

=cut


