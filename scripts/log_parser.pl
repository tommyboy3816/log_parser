#! /usr/bin/perl -w

use IO::File;
use Getopt::Long;
use vars qw/$opt_g/;
use strict;

my ($filename, $ii, $jj, $kk, $hh, $ipaddr, $port);
my (@tmp, @counts);
my (%ack_scan, %synack_scan, %tcpudp_chargen, %rst_scan);


GetOptions('f=s' => \$filename);

print $filename . "\n";

if( $filename )
{
	my $fh = new IO::File $filename, "r";
	if( defined $fh )
	{
		@tmp = <$fh>;
	}
	else
	{
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
			if( $line =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\, port (\d{1,5})/ ) {
				$ipaddr = $1;
				$port = $2;
				$rst_scan{$ipaddr}{$port}++;
			}
			printf("%6d) %s\n", $ii, $line);
			printf("\tIP %s, port %d\n", $ipaddr, $port);

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
	
	}
	else {
		$hh++;
		#printf("%6d) %s\n", $hh, $line);
	}
}

my @ips = keys %rst_scan;
printf("RST Scan Hits from IP:Port...\n");
printf("---------------------------------------\n");
foreach my $ip (keys %rst_scan) {
    while (my ($key, $value) = each %{ $rst_scan{$ip} } ) {
        print "$ip:$key = $value \n";
    }
}

# Assign a list of array references to an array.
my @AoA = (
         [ "fred", "barney" ],
         [ "george", "jane", "elroy" ],
         [ "homer", "marge", "bart" ],
);

print $AoA[0][0];   # prints "fred"

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

