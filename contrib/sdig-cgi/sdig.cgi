#!/usr/bin/perl

### $Id: $
### SDig-0.45 web interface wrapper
### (C) Nov 15 2003 - Oct 11 2005 by Jim Klimov, bofh@campus.mipt.ru (Linux)
###     Initial writeup for sdig versions 0.30-0.43
### (C) Jul 09-26 2010 by Jim Klimov, jimklimov@cos.ru (Solaris, config files)
###	Remake for sdig version 0.45
### Credits for routines go to various authors on the Web :)
### See http://sdig.sourceforge.net/ for utility source
### Previously http://www.exploits.org/sdig, now gone

##########################################################
### Here are some site-specific configuration variables
### They can (and should) be overriden by config files:
### personal $HOME/.sdig-cgi.conf overrides global /etc/sdig-cgi.conf

### If desired to trim IPs to known local networks, define this regexp:
### If not defined, any IP will be searched
# $ipMask = '^(192\.168\.8[0-5]|194\.85\.8[0-3]|81\.5\.8[0-7]|10\.84\.\d{1,3}|10\.10\.[12345678]0)\.\d{1,3}$';
$ipMask = '^(192\.168\.\d{1,3}|10\.(55|84)\.\d{1,3}|172\.16\.[12345678]0)\.\d{1,3}$';

### Pre-fill the HTML request table with one or more strings?
#$HTML_DEFAULT_IP="";
#$HTML_DEFAULT_MAC="";
#$HTML_DEFAULT_HOST="";

### Define an IP to substitute for SDIG call when searching by MAC (ignored)
$defaultIP = '127.0.0.1';

### This MAC of router answers as ARP cache on VLAN84
### (you can provide several MACs as regexp)
$ROUTERMAC='00:16:9C:70:34:00';

### SDig Binary
$BINSDIG = "/usr/local/bin/sdig";
$BINSDIGPING = "/usr/local/bin/sdig-preamble";

### If unset, a hardcoded default will be used.
### Can override in private configs.
#$CFGSDIG = "/etc/sdig.conf";

### Export typical Solaris PATHs
$ENV{LD_LIBRARY_PATH} = "$ENV{LD_LIBRARY_PATH}:/usr/sfw/lib:/opt/sfw/lib:/usr/local/lib:/usr/lib:/lib";

### The rest is quite generic and shouldn't be changed
##########################################################

### Show some extra diags during development?
### (Got a hidden form field for GET URL like '&debug_sdig=10')
$debug = 0;
$debug_sdig = 0;

my $def_debug = $debug;
sub readCfg {
    my ($cfgFile) = ( @_ );

#    global $debug, $debug_sdig, $ipMask, $defaultIP, $ROUTERMAC, $BINSDIG, $BINSDIGPING, $CFGSDIG, $HTML_DEFAULT_MAC, $HTML_DEFAULT_HOST, $HTML_DEFAULT_IP;

    ### Normally this would end up in server's error log
    if ( $def_debug > 2 ) { print stderr "=== Reading cfgFile='$cfgFile'\n"; }

    if ( -r "$cfgFile" ) {
	if ( $def_debug > 2 ) { print stderr "=== OPENING cfgFile='$cfgFile'\n"; }
	open F, $cfgFile or return 1;
	while (<F>) {
	    chomp;                  # no newline
	    s/#.*//;                # no comments
	    s/^\s+//;               # no leading white
	    s/\s+$//;               # no trailing white
	    next unless length;     # anything left?
	    my ($var, $value) = split(/\s*=\s*/, $_, 2);
	    $value =~ s/^['"](.*)['"]$/\1/;
	    if ( $var =~ /^(debug|debug_sdig|ipMask|defaultIP|ROUTERMAC|BINSDIG|BINSDIGPING|CFGSDIG|HTML_DEFAULT_MAC|HTML_DEFAULT_HOST|HTML_DEFAULT_IP)$/ ) {
		$$var = $value;

		if ( $def_debug > 1 ) { print stderr "VAR = $var, VAL = '$value'; \$\$var = '$$var'\n"; }
	    }
	}
	if ( $def_debug > 1 ) { print STDERR "=== Finished cfgFile='$cfgFile'\n"; print STDERR "\n"; }
	close F;
	return 0;
    }
    return 1;
}

### Pull in config files to override these defaults
if ( readCfg("$ENV{HOME}/.sdig-cgi.conf") == 0 ) {
    if ( $def_debug > 1 ) { print stderr "Success 1\n"; }
} elsif ( readCfg ("/etc/sdig-cgi.conf") == 0 ) {
    if ( $def_debug > 1 ) { print stderr "Success 2\n"; }
}

my(%frmFlds);

getFormData(\%frmFlds);

sub getFormData {

    my($hashRef) = shift;
    my($buffer) = "";

    if ($ENV{'REQUEST_METHOD'} eq 'GET') {
        $buffer = $ENV{'QUERY_STRING'};
    } else {
        read(STDIN, $buffer, $ENV{'CONTENT_LENGTH'});
    }

    foreach (split(/&/, $buffer)) {
        my($key, $value) = split(/=/, $_);
        $key   = decodeURL($key);
        $value = decodeURL($value);
        %{$hashRef}->{$key} = $value;
    }
}

sub decodeURL {
    $_ = shift;
    tr/+/ /;
    s/%(..)/pack('c', hex($1))/eg;
    return($_);
}

sub checkIP {
    ### See if passed string is an IP we accept
    ( $teststr ) = @_;
    chomp $teststr;

    local ($ip);
    $ip = "";

    if ( $teststr =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ) {
	if ( "x$ipMask" ne "x" ) {
	    print "<pre>Have IP Mask: '$ipMask'</pre>\n" if ( $debug > 0 );
	    ### We know networks we have
    	    if ( $teststr =~ /$ipMask/ ) {
		$ip = $teststr;
	    } else {
		print "<b>Submitted IP ($teststr) is not in a defined set of supported networks!</b></br>\n";
	    }
        } else {
	    ### Anything like an IP is ok
	    $ip = $teststr;
	}
    }

    return $ip;
}

sub checkMAC {
    ### See if passed string is a MAC we accept
    ( $teststr ) = @_;
    chomp $teststr;

    local ($mac);
    $mac = "";

    ### Normalize a MAC address to sdig compatible format
    ### For the sake of readability i don't use {} regexp syntax here
    if ( $teststr =~ /^([0-9A-Fa-f][0-9A-Fa-f]\:[0-9A-Fa-f][0-9A-Fa-f]\:[0-9A-Fa-f][0-9A-Fa-f]\:[0-9A-Fa-f][0-9A-Fa-f]\:[0-9A-Fa-f][0-9A-Fa-f]\:[0-9A-Fa-f][0-9A-Fa-f])$/ ) {
	### Usual mac address as xx:xx:xx:xx:xx:xx ok for sdig
        $mac = $teststr;
    } elsif ( $teststr =~ /^([0-9A-Fa-f]?[0-9A-Fa-f])\:([0-9A-Fa-f]?[0-9A-Fa-f])\:([0-9A-Fa-f]?[0-9A-Fa-f])\:([0-9A-Fa-f]?[0-9A-Fa-f])\:([0-9A-Fa-f]?[0-9A-Fa-f])\:([0-9A-Fa-f]?[0-9A-Fa-f])$/ ) {
	### Solaris mac address as xx:xx:xx:xx:xx:xx almost ok for sdig
	### Can be missing leading zero's, i.e. "0:14:4f:2:5b:fc"
	### Expand the missing zeros
        $mac = $teststr;
	$mac =~ s/([^0-9A-Fa-f]|^)([0-9A-Fa-f])([^0-9A-Fa-f]|$)/\1X\2\3/g;
	$mac =~ s/X/0/g;
    } elsif ( $teststr =~ /^([0-9A-Fa-f][0-9A-Fa-f]-[0-9A-Fa-f][0-9A-Fa-f]-[0-9A-Fa-f][0-9A-Fa-f]-[0-9A-Fa-f][0-9A-Fa-f]-[0-9A-Fa-f][0-9A-Fa-f]-[0-9A-Fa-f][0-9A-Fa-f])$/ ) {
	### Windows mac address as xx-xx-xx-xx-xx-xx
        $mac = $teststr;
	$mac =~ s/\-/\:/g;
    } elsif ( $teststr =~ /^([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])\.([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])\.([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])$/ ) {
	### Cisco mac: xxxx.xxxx.xxxx
        $mac = "$1:$2:$3:$4:$5:$6";
    } elsif ( $teststr =~ /^([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])-([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])([0-9A-Fa-f][0-9A-Fa-f])$/ ) {
	### HP mac: xxxxxx-xxxxxx
        $mac = "$1:$2:$3:$4:$5:$6";
    } elsif ( $teststr =~ /^([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])([0-9A-Fa-f])$/ ) {
	### Unseparated mac: xxxxxxxxxxxx
	$mac = "$1$2:$3$4:$5$6:$7$8:$9$10:$11$12";
    }

    $mac = lc($mac);

    return $mac;
}

sub checkHOST {
    ### See if passed string is a hostname we accept
    ( $teststr ) = @_;
    chomp $teststr;

    local ($host);
    $host = "";

    ### Check that host is a QDN (or FQDN) string
    if ( $teststr =~ /^[\w]*(\.[\w]*)*$/ ) {
	$host = $teststr;
    }

    return $host;
}

sub checkDEBUG {
    ### See if passed string is an integer
    ( $teststr ) = @_;
    chomp $teststr;

    local ($dbg);
    $dbg = "";

    if ( $teststr =~ /^\d+$/ ) {
	if ( $teststr >= 0 ) {
	    $dbg = $teststr;
	}
    }

    return $dbg;
}

print "Content-Type: text/html\n\n";
print "<html><head><title>SDig: Switch Digger interface</title></head><body>\n";

### Check $ip value
$ip = &checkIP ( $frmFlds{'ip'} );

### Check that host is a QDN (or FQDN) string
$host = &checkHOST ( $frmFlds{'host'} );

### Normalize a MAC address to sdig compatible format
$mac = &checkMAC ( $frmFlds{'mac'} );

if ( defined($frmFlds{'debug'}) ) {
    $dbg = &checkDEBUG ( $frmFlds{'debug'} );
    if ( $dbg ne "" ) {
	$debug = $dbg;
    }
}

if ( defined($frmFlds{'debug_sdig'}) ) {
    $dbg = &checkDEBUG ( $frmFlds{'debug_sdig'} );
    if ( $dbg ne "" ) {
	$debug_sdig = $dbg;
    }
}

if ( $ip eq "" && $mac eq "" && $host eq "" ) {
    print "<p>SDig.cgi is an interface to 
<a href='http://sdig.sourceforge.net/'>sdig</a> utility and allows 
admins to quickly locate an interesting IP and/or MAC-address 
and match it to a switch port.</p>
<p>Please enter some request data: IP or HOST (local to your net) 
or MAC-address (general, Cisco or contiguous format) to seek:<br>
<form action='$ENV{'SCRIPT_NAME'}' method=GET>
MAC  : <input type=text value='".$HTML_DEFAULT_MAC."' name=mac size=20><br>
IP   : <input type=text value='".$HTML_DEFAULT_IP."' name=ip size=20><br>
HOST : <input type=text value='".$HTML_DEFAULT_HOST."' name=host size=20><br>
<input type=submit>
</form></p>\n";

    print "<p>Prev form data: 
MAC='<tt>$mac</tt>' <small>(<tt>$frmFlds{'mac'}</tt>)</small>,
IP='<tt>$ip</tt>' <small>(<tt>$frmFlds{'ip'}</tt>)</small>, 
HOST='<tt>$host</tt>' <small>(<tt>$frmFlds{'host'}</tt>)</small></p>";

} else {

    print "<p>Prev form data: 
MAC='<tt>$mac</tt>' <small>(<tt>$frmFlds{'mac'}</tt>)</small>,
IP='<tt>$ip</tt>' <small>(<tt>$frmFlds{'ip'}</tt>)</small>, 
HOST='<tt>$host</tt>' <small>(<tt>$frmFlds{'host'}</tt>)</small></p>";

    $mac_flag = "";
    if ( $mac ne "" ) {
	print "<p>Digging for MAC '<tt>$mac</tt>':";
	### not required since sdig-0.45
	### if ( $ip eq "" ) { $ip = $defaultIP; }
	$host = '';
	$mac_flag = "-m $mac";
    } elsif ( $ip ne "" ) {
	print "<p>Digging for IP '<tt>$ip</tt>':";
	$host = '';
    } elsif ( $host ne "" ) {
	print "<p>Digging for HOST '<tt>$host</tt>':";
	$ip = '';
    }
    print "<br><tt>$BINSDIG $mac_flag $ip $host</tt><br>Please wait a little (~20-30 sec)...<br><hr><br><pre>\n";

### Flush now:
    { my $ofh = select stdout;
	$| = 1;		# Make handle HOT
	print "";	# Use it
	print stdout "";	# Use it
	$| = 0;		# Un-HOT it
	select $ofh;
    }
    { my $ofh = select stderr;
	$| = 1;		# Make handle HOT
	print stderr "";	# Use it
	$| = 0;		# Un-HOT it
	select $ofh;
    }
    { my $ofh = select STDOUT;
	$| = 1;		# Make handle HOT
	print STDOUT "";	# Use it
	$| = 0;		# Un-HOT it
	select $ofh;
    }
    { my $ofh = select STDERR;
	$| = 1;		# Make handle HOT
	print STDERR "";	# Use it
	$| = 0;		# Un-HOT it
	select $ofh;
    }
#    flush STDOUT;
#    flush STDERR;
### Unneeded vars should be empty now

    if ( $debug > 0 ) { system("id"); }

    $OK = 0;

    if ( $debug_sdig ) {
	print "<br>debug_sdig flag = $debug_sdig<br>\n";
    }

    $debug_sdig_flag = "";
    while ( $debug_sdig-- > 0 ) {
	$debug_sdig_flag .= "d";
    }
    if ( "$debug_sdig_flag" ne "" ) {
	$debug_sdig_flag = " -".$debug_sdig_flag;
    }

    $CFGFLAG="";
    if ( "$CFGSDIG" ne "" && -r "$CFGSDIG" ) { $CFGFLAG=" -f $CFGSDIG "; }
    ### First run pings then sdigs (may take quite some time)
    ### For users' sake we try to ping and display the result
    if ( $ip ne "" && -x "$BINSDIGPING" ) {
	### For known IP we can start displaying pingability then dig
	system ( "$BINSDIGPING $ip ");
	print "=== $BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip $host\n";
	$OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip $host 2>&1`;
    } elsif ( $host ne "" && -x "$BINSDIGPING" ) {
	### For known hostname we can start displaying pingability then dig
	system ( "$BINSDIGPING $host ");
	print "=== $BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip $host\n";
	$OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip $host 2>&1`;
    } else {
	### SDig in non-Fast mode calls its preamble, but we wait longer to see it
	print "=== $BINSDIG $debug_sdig_flag $CFGFLAG $mac_flag $ip $host\n";
	$OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG $mac_flag $ip $host 2>&1`;
    }
    print "<hr>\n$OUT\n<hr>\n";
    sleep 5;
    if ( $OUT =~ /Port:/ && $OUT !~ /Port:\s+0\s*/ ) { $OK = 1; }

    if ( $OK == 1 ) {
	print "=== Successfully completed\n";
    } else {
	### Second run only sdigs if we know target's MAC
	if ( $mac eq "" ) {
	    if ( $ip eq "" && $host ne "" ) {
		$str = `host $host | grep 'has address' | awk '{print \$4}'`;
		chomp $str;
		$ip = &checkIP ( $str );
	    }
	    if ( $ip ne "" ) {
		if ( "`uname -s`" eq "Linux" ) {
		    $str = `arp -n "$ip" | grep "$ip" | grep ether | awk '{ print \$3 }'`;
		} elsif ( "`uname -s`" eq "SunOS" ) {
		    $str = `arp -an | grep "$ip" | awk '{ print \$5 }'`;
		}
		chomp $str;
		$mac = &checkMAC ( $str );
		$mac_flag = "-m $mac";
	    }
	}
	if ( $mac eq "" && $ip ne "" ) {
	    ### Last resort: find local interface's mac
	    if ( "`uname -s`" eq "Linux" ) {
		$str = `ifconfig -a | grep -A1 HWaddr | grep -B1 $ip | grep HWaddr | awk '{ print \$5 }'`;
	    } elsif ( "`uname -s`" eq "SunOS" ) {
		$str = `ifconfig -a | ggrep -B1 ether | ggrep -A1 $ip | grep ether | awk '{ print \$2 }'`;
	    }
	    $mac = &checkMAC ( $str );
	    $mac_flag = "-m $mac";
	}
	if ( $mac ne "" && $mac !~ /$ROUTERMAC/i ) {
	    print "!!! Some error occurred when searching by IP, but we seem to know its MAC ($mac):\n";

	    $OK = 0;

	    print "=== $BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip\n";
	    $OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG -F $mac_flag $ip 2>&1`;
	    if ( $OUT =~ /Port:/ && $OUT !~ /Port:\s+0\s*/ ) { $OK = 1; }
	    print "<hr>\n$OUT\n<hr>\n";

	    if ( $OK == 1 ) {
		print "=== Successfully completed\n";
	    }
	} else {
	    print "Can't find a MAC for it on local server, can't retry :(\n";
	}

	if ( $OK != 1 ) {
	    ### Third run, verbose, if first or both failed
	    $OK = 0;

	    print "!!! Trying a verbose/debug run to see all switch ports that know this ip\n";

	    if ( $mac ne "" && $mac !~ /$ROUTERMAC/i ) {
		print "!!! and mac ($mac)\n";
		print "=== $BINSDIG $debug_sdig_flag $CFGFLAG -F -vPP $mac_flag $ip\n";
		$OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG -F -vPP $mac_flag $ip 2>&1`;
	    } else {
		print "=== $BINSDIG $debug_sdig_flag $CFGFLAG -F -vPP $ip\n";
		$OUT = `$BINSDIG $debug_sdig_flag $CFGFLAG -F -vPP $ip 2>&1`;
	    }
	    if ( $OUT =~ /Port:/ && $OUT !~ /Port:\s+0\s*/ ) { $OK = 1; }

	    if ( $OK == 1 ) {
		print "=== Successfully completed, as much as we could find...\n";
	    } else {
		print "!!! Still not found, aborting!\n";
	    }
	}
    }
    print "</pre><hr><br>";

    print "<p><a href='$ENV{'SCRIPT_NAME'}'>New query</a></p>\n";
}

# print "<pre>$ipMask</pre>\n";

print "</body></html>\n";
