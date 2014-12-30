#!/usr/bin/perl -w
# nagios: +epn
#
# This plugin uses the FCMGMT-MIB (under experimental) to query SAN switches
# for stats about their environment/chassis sensors
#
############################## check_snmp_int ##############
my $Version='1.0';
# Date : Apr 14, 2012
# Author  : Brent Bice
# Help : http://nagios.manubulon.com
# Licence : GPL - http://www.fsf.org/licenses/gpl.txt
# Contrib : Patric Proy, J. Jungmann, S. Probst, R. Leroy, M. Berger
# TODO : 
#################################################################
#
# Help : ./sgichk_sansw_chassis.pl -h
#
use strict;
use Net::SNMP;
use Getopt::Long;

# Nagios specific

my $TIMEOUT = 15;
my %ERRORS=('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);

# SNMP Datas

my $status_table= '.1.3.6.1.3.94.1.8.1.4';
my $name_table = '.1.3.6.1.3.94.1.8.1.3';
my $msg_table = '.1.3.6.1.3.94.1.8.1.6';

my %status=(1=>'UNKNOWN',2=>'OTHER',3=>'OK',4=>'WARNING',5=>'FAILED');

# Globals


# Standard options
my $o_host = 		undef; 	# hostname
my $o_port = 		161; 	# port
my $o_help=		undef; 	# wan't some help ?
my $o_verb=		undef;	# verbose mode
my $o_version=		undef;	# print version
my $o_warn_opt=		undef;  # warning options
my $o_crit_opt=		undef;  # critical options
my @o_warn=		undef;  # warning levels of perfcheck
my @o_crit=		undef;  # critical levels of perfcheck

my $o_timeout=  undef; 		# Timeout (Default 5)
# SNMP Message size parameter (Makina Corpus contrib)
my $o_octetlength=undef;
# Login options specific
my $o_community = 	undef; 	# community
my $o_version1	= undef;	#use snmp v1
my $o_version2	= undef;	#use snmp v2c
my $o_login=	undef;		# Login for snmpv3
my $o_passwd=	undef;		# Pass for snmpv3
my $v3protocols=undef;	# V3 protocol list.
my $o_authproto='md5';		# Auth protocol
my $o_privproto='des';		# Priv protocol
my $o_privpass= undef;		# priv password

# functions

sub p_version { print "check_snmp_int version : $Version\n"; }

sub print_usage {
    print "Usage: $0 [-v] -H <host> -C <snmp_community> [-2] | (-l login -x passwd [-X pass -L <authp>,<privp>)  [-p <port>] [-o <octet_length>] [-t <timeout>] [-V]\n";
}

sub isnnum { # Return true if arg is not a number
  my $num = shift;
  if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0 ;}
  return 1;
}

sub help {
   print "\nSNMP SAN Switch Chassis Monitor for Nagios version ",$Version,"\n";
   print "GPL licence, (c)2012 Brent Bice\n\n";
   print_usage();
   print <<EOT;
-v, --verbose
   print extra debugging information (including interface list on the system)
-h, --help
   print this help message
-H, --hostname=HOST
   name or IP address of host to check
-C, --community=COMMUNITY NAME
   community name for the host's SNMP agent (implies v1 protocol)
-l, --login=LOGIN ; -x, --passwd=PASSWD, -2, --v2c
   Login and auth password for snmpv3 authentication 
   If no priv password exists, implies AuthNoPriv 
   -2 : use snmp v2c
-X, --privpass=PASSWD
   Priv password for snmpv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
   <authproto> : Authentication protocol (md5|sha : default md5)
   <privproto> : Priv protocole (des|aes : default des) 
-P, --port=PORT
   SNMP port (Default 161)
-o, --octetlength=INTEGER
  max-size of the SNMP message, usefull in case of Too Long responses.
  Be carefull with network filters. Range 484 - 65535, default are
  usually 1472,1452,1460 or 1440.     
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)   
-V, --version
   prints version number
EOT
}

# For verbose output
sub verb { my $t=shift; print $t,"\n" if defined($o_verb) ; }

sub check_options {
    Getopt::Long::Configure ("bundling");
	GetOptions(
   	'v'	=> \$o_verb,		'verbose'	=> \$o_verb,
        'h'     => \$o_help,    	'help'        	=> \$o_help,
        'H:s'   => \$o_host,		'hostname:s'	=> \$o_host,
        'p:i'   => \$o_port,   		'port:i'	=> \$o_port,
        'C:s'   => \$o_community,	'community:s'	=> \$o_community,
	'2'	=> \$o_version2,	'v2c'		=> \$o_version2,		
	'1'	=> \$o_version1,	'v1'		=> \$o_version1,
	'l:s'	=> \$o_login,		'login:s'	=> \$o_login,
	'x:s'	=> \$o_passwd,		'passwd:s'	=> \$o_passwd,
	'X:s'	=> \$o_privpass,		'privpass:s'	=> \$o_privpass,
	'L:s'	=> \$v3protocols,		'protocols:s'	=> \$v3protocols,   
        't:i'   => \$o_timeout,    	'timeout:i'	=> \$o_timeout,
	'o:i'   => \$o_octetlength,    	'octetlength:i' => \$o_octetlength
    );
    if (defined ($o_help) ) { help(); exit $ERRORS{"UNKNOWN"}};
    if (defined($o_version)) { p_version(); exit $ERRORS{"UNKNOWN"}};
    if ( ! defined($o_host) ) # check host
	{ print_usage(); exit $ERRORS{"UNKNOWN"}}

    # check snmp information
    if ( !defined($o_community) && (!defined($o_login) || !defined($o_passwd)) )
	{ print "Put snmp login info!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if ((defined($o_login) || defined($o_passwd)) && (defined($o_community) || defined($o_version2)) )
	{ print "Can't mix snmp v1,2c,3 protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if (defined ($v3protocols)) {
	  if (!defined($o_login)) { print "Put snmp V3 login info with protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	  my @v3proto=split(/,/,$v3protocols);
	  if ((defined ($v3proto[0])) && ($v3proto[0] ne "")) {$o_authproto=$v3proto[0];	}	# Auth protocol
	  if (defined ($v3proto[1])) {$o_privproto=$v3proto[1];	}	# Priv  protocol
	  if ((defined ($v3proto[1])) && (!defined($o_privpass))) {
	    print "Put snmp V3 priv login info with priv protocols!\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	}
	if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) 
	  { print "Timeout must be >1 and <60 !\n"; print_usage(); exit $ERRORS{"UNKNOWN"}}
	if (!defined($o_timeout)) {$o_timeout=5;}

    #### octet length checks
    if (defined ($o_octetlength) && (isnnum($o_octetlength) || $o_octetlength > 65535 || $o_octetlength < 484 )) {
		print "octet lenght must be < 65535 and > 484\n";print_usage(); exit $ERRORS{"UNKNOWN"};
    }	
}
    
########## MAIN #######

check_options();

# Check gobal timeout if snmp screws up
if (defined($TIMEOUT)) {
  verb("Alarm at $TIMEOUT + 5");
  alarm($TIMEOUT+5);
} else {
  verb("no timeout defined : $o_timeout + 10");
  alarm ($o_timeout+10);
}

$SIG{'ALRM'} = sub {
 print "No answer from host\n";
 exit $ERRORS{"UNKNOWN"};
};

# Connect to host
my ($session,$error);
if ( defined($o_login) && defined($o_passwd)) {
  # SNMPv3 login
  if (!defined ($o_privpass)) {
  verb("SNMPv3 AuthNoPriv login : $o_login, $o_authproto");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -version		=> '3',
      -port      	=> $o_port,
      -username		=> $o_login,
      -authpassword	=> $o_passwd,
      -authprotocol	=> $o_authproto,
      -timeout          => $o_timeout
    );  
  } else {
    verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto");
    ($session, $error) = Net::SNMP->session(
      -hostname   	=> $o_host,
      -version		=> '3',
      -username		=> $o_login,
      -port      	=> $o_port,
      -authpassword	=> $o_passwd,
      -authprotocol	=> $o_authproto,
      -privpassword	=> $o_privpass,
	  -privprotocol => $o_privproto,
      -timeout          => $o_timeout
    );
  }
} else {
  if (defined ($o_version2)) {
    # SNMPv2c Login
	verb("SNMP v2c login");
	($session, $error) = Net::SNMP->session(
       -hostname  => $o_host,
	   -version   => 2,
       -community => $o_community,
       -port      => $o_port,
       -timeout   => $o_timeout
    );
  } else {
    # SNMPV1 login
	verb("SNMP v1 login");
    ($session, $error) = Net::SNMP->session(
       -hostname  => $o_host,
       -community => $o_community,
       -port      => $o_port,
       -timeout   => $o_timeout
    );
  }
}
if (!defined($session)) {
   printf("ERROR opening session: %s.\n", $error);
   exit $ERRORS{"UNKNOWN"};
}

if (defined($o_octetlength)) {
	my $oct_resultat=undef;
	my $oct_test= $session->max_msg_size();
	verb(" actual max octets:: $oct_test");
	$oct_resultat = $session->max_msg_size($o_octetlength);
	if (!defined($oct_resultat)) {
		 printf("ERROR: Session settings : %s.\n", $session->error);
		 $session->close;
		 exit $ERRORS{"UNKNOWN"};
	}
	$oct_test= $session->max_msg_size();
	verb(" new max octets:: $oct_test");
}

# Get status table
my $resultstat = $session->get_table( Baseoid => $status_table );
if (!defined($resultstat)) {
   printf("ERROR: Status table : %s.\n", $session->error);
   $session->close;
   exit $ERRORS{"UNKNOWN"};
}

my $resultname = $session->get_table(Baseoid => $name_table);
if (!defined($resultname)) {
   printf("ERROR: Sensor Name table : %s.\n", $session->error);
   $session->close;
   exit $ERRORS{"UNKNOWN"};
}

my $resultmsg = $session->get_table(Baseoid => $msg_table);
if (!defined($resultmsg)) {
   printf("ERROR: Sensor message table : %s.\n", $session->error);
   $session->close;
   exit $ERRORS{"UNKNOWN"};
}

$session->close;

# Only a few ms left...
alarm(0);


my $num_sensor = 0;

# define the OK value depending on -i option
my $ok_val= 3; # As defined in the MIB
my $print_out = "";
my $num_bad=0;
my $result = $ERRORS{"OK"};   # assume all will be well

my @outstr = ();
my $perfstr = "\|";
foreach my $key ( keys %$resultstat) {
   #verb("OID : $key, Desc : $$resultstat{$key}");
   my $stat = $$resultstat{$key};

   # Apparently a status of UNKNOWN usually means some fan or temp
   # sensor doesn't exist and isn't therefore an error condition
   if (($stat == 2) && ($result == $ERRORS{'OK'})) {
      $result = $ERRORS{'UNKNOWN'}; $num_bad++;
   } elsif (($stat == 4) && ($result != $ERRORS{'CRITICAL'})) {
      $result = $ERRORS{'WARNING'}; $num_bad++;
   } elsif ($stat == 5) {
      $result = $ERRORS{'CRITICAL'}; $num_bad++;
   }

   my $sensorid = "";
   if ($key =~ /$status_table\.(.*)/) {
      $sensorid = $1;
      my $msg = $$resultmsg{$msg_table . "." . $sensorid};
      my $name = $$resultname{$name_table . "." . $sensorid};
      $name =~ s/[ \#]/_/g;   # cleanup name

      my $statstr = "$name: $status{$stat} - $msg";
      push (@outstr, $statstr);
      verb($statstr);

      # look for perf stats in message
      if (($msg =~ /value is ([0-9.]+)/) ||
          ($msg =~ /^([0-9.]+)/)
         ) {
         $perfstr .= " $name=$1";
      }
   }
}

verb ("perfstr = $perfstr");

if ($result == $ERRORS{'OK'}) {
   print "OK: All sensors ok $perfstr\n";
} elsif ($result == $ERRORS{'UNKNOWN'}) {
   print "UNKNOWN: $num_bad sensors not ok $perfstr\n";
} elsif ($result == $ERRORS{'WARNING'}) {
   print "WARNING: $num_bad sensors not ok $perfstr\n";
} elsif ($result == $ERRORS{'CRITICAL'}) {
   print "CRITICAL: $num_bad sensors not ok $perfstr\n";
}

foreach my $i (@outstr) {
   print "$i\n";
}
exit $result;

