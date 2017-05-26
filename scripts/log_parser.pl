#! /usr/bin/perl -w

use IO::File;
use Getopt::Long;
use vars qw/$opt_g/;
use strict;

my ($filename, $ii, $jj, $kk, $ll, $hh, $ipaddr, $port);
my (@tmp, @counts);
my (%ack_scan, %synack_scan, %tcpudp_chargen, %rst_scan, %arp_attack, %tcpudp_echo, %udp_portscan);


GetOptions('f=s' => \$filename);

print $filename . "\n";

if( $filename ) {
	my $fh = new IO::File $filename, "r";
	if( defined $fh ) {
		@tmp = <$fh>;
	}
	else {
		die "did not find $filename\n";
	}
}

foreach my $line (@tmp)
{
	# Remove any trailing spaces/newlines
	$line =~ s/\s+$//g;

	if( $line =~ m/DoS Attack/ ) {
		$ii++;
		if( $line =~ m/RST Scan/ ) {
			parse_log_string($line, \%rst_scan);
			#if( $line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\, port (\d{1,5})/ ) {
			#	$ipaddr = $1;
			#	$port = $2;
			#	$rst_scan{$ipaddr}{$port}++;
			#}
			#printf("%6d) %s\n", $ii, $line);
			#printf("\tIP %s, port %d\n", $ipaddr, $port);

		}
		elsif( $line =~ m/SYN\/ACK Scan/ ) {
			parse_log_string( $line, \%synack_scan );
		}
		elsif( $line =~ m/ACK Scan/ ) {
			parse_log_string( $line, \%ack_scan );
		}
		elsif( $line =~ m/TCP\/UDP Chargen/ ) {
			parse_log_string( $line, \%tcpudp_chargen );
		}
		elsif( $line =~ m/ARP Attack/ ) {
			parse_log_string( $line, \%arp_attack );	
		}
		elsif( $line =~ m/TCP\/UDP Echo/ ) {
			parse_log_string( $line, \%tcpudp_echo );
		}
		elsif( $line =~ m/UDP Port Scan/ ) { 
			parse_log_string( $line, \%udp_portscan );
		}
		else {
			printf("LOG ENTRY NOT SUPPORTED\n\t%s\n", $line);
		}
	}
	elsif( $line =~ /DHCP IP/ ) {
		$jj++;
		#printf("%6d) %s\n", $jj, $line);
	}
	elsif( $line =~ /UPnP set event/ ) {
		$kk++;
		#printf("%6d) %s\n", $kk, $line);
	}
	elsif( $line =~ /LAN access from remote/ ) {
	
	}
	elsif( $line =~ /WLAN access rejected/ ) {
		$ll++;
		printf("%6d) %s\n", $ll, $line);	
	}
	elsif( $line =~ /admin login/ ) {

	}
	elsif( $line =~ /Time synchronized/ ) {

	}
	else {
		$hh++;
		printf("%6d) %s\n", $hh, $line);
	}
}

$jj = 1;
printf("RST Scan Hits from IP:Port...(%d hosts)\n", scalar(keys %rst_scan));
printf("---------------------------------------\n");
foreach my $ip (keys %rst_scan) {
    while (my ($key, $value) = each %{ $rst_scan{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}

printf("\n\nSYN/ACK Scan Hits from IP:Port...(%d hosts)\n", scalar(keys %synack_scan));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %synack_scan) {
    while (my ($key, $value) = each %{ $synack_scan{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}


printf("\n\nACK Scan Hits from IP:Port...(%d hosts)\n", scalar(keys %ack_scan));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %ack_scan) {
    while (my ($key, $value) = each %{ $ack_scan{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}


printf("\n\nTCP/UDP Chargen Hits from IP:Port...(%d hosts)\n", scalar(keys %tcpudp_chargen));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %tcpudp_chargen) {
    while (my ($key, $value) = each %{ $tcpudp_chargen{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}

printf("\n\n ARP Attack Hits from IP:Port...(%d hosts)\n", scalar(keys %arp_attack));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %arp_attack) {
    while (my ($key, $value) = each %{ $arp_attack{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}

printf("\n\n TCP/UDP Echo Hits from IP:Port...(%d hosts)\n", scalar(keys %tcpudp_echo));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %tcpudp_echo) {
    while (my ($key, $value) = each %{ $tcpudp_echo{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}

printf("\n\n UDP Port Scan Hits from IP:Port...(%d hosts)\n", scalar(keys %udp_portscan));
printf("---------------------------------------\n");
$jj = 1;
foreach my $ip (keys %udp_portscan) {
    while (my ($key, $value) = each %{ $udp_portscan{$ip} } ) {
        printf("%3d) %s:%d = %d\n", $jj++, $ip, $key, $value);
    }
}






# Assign a list of array references to an array.
#my @AoA = (
#         [ "fred", "barney" ],
#         [ "george", "jane", "elroy" ],
#         [ "homer", "marge", "bart" ],
#);
#print $AoA[0][0];   # prints "fred"

#
#
#
sub parse_log_string
{
	my $logline = shift;
	my $hashref = shift;


	# This line should be first
	if( $logline =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\, port (\d{1,5})/ ) {
		my $ipaddr = $1;
		my $port = $2;
		$hashref->{$ipaddr}->{$port}++;
	}
	elsif( $logline =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/ ) {
		my $ipaddr = $1;
		my $port = 0xffff;
		$hashref->{$ipaddr}->{$port}++;
	}

	#printf("\tIP %s, port %d\n", $ipaddr, $port);
}

#
# Walk through the hashes
#
sub traverse {
    if( ref( $_[0] ) =~ /HASH/ ) {
        traverse( $_[0]{$_} ) foreach keys %{$_[0]};
    } else {
        print "$_[0]\n";
    }
}

