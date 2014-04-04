#!/usr/bin/perl

use strict;
use DBI;
use Net::DNS;
use Digest::MD5;

# Where we stash our working files
my $basedir = "/tmp";
chdir $basedir;


# Master server
my $authserver = "192.168.80.101";

# Tinydns slave servers
my @slaves = qw/10.11.12.13 172.16.17.18/;

# Modify this to be in one of your zones
my $sigrecord = 'signature.example.com';

# Fetch list of zones - only use of direct database access
my $dbh = DBI->connect("dbi:Pg:dbname=powerdns", 'pdns', '', {AutoCommit => 0, RaiseError => 1});
my @zones = @{$dbh->selectcol_arrayref('select name from domains')};
$dbh->disconnect;

my $workdir = "$basedir/zones";

-d $workdir || mkdir $workdir;
-d $workdir || die "Failed to find working directory $workdir\n";

my %records;

foreach my $zone (@zones) {
    my $filename = "$workdir/$zone.zone";
    my $tempfile = "$filename.tmp";
    my @args = ('tcpclient', '-H', '-R', $authserver, '53', 'axfr-get', $zone, $filename, $tempfile);
    unless(system(@args) == 0) {
	print STDERR "Failed to run '@args': $?\n";
	if ($? == -1) {
	    print "failed to execute: $!\n";
	}
	elsif ($? & 127) {
	    printf "child died with signal %d, %s coredump\n",
	    ($? & 127),  ($? & 128) ? 'with' : 'without';
	}
	else {
	    printf "child exited with value %d\n", $? >> 8;
	}
	die "Giving up\n";
    }
    open IF, $filename or die "Failed to open $filename\n";
    while(<IF>) {
	chomp;
	$records{$_}=1;
    }
}

open OF, ">$basedir/data" or die "Failed to create $basedir/data: $!\n";

my $md5 = Digest::MD5->new;

foreach my $record (sort keys %records) {
    $record =~ s/\\052/*/g;
    # Goddamn dumb axfr-get doesn't understand TXT records
    if($record =~ /^:([^:]+):16:(\\\d{3}|[^\\])([^:]+):(.*)$/) {
	my $lhs = $1;
	my $length = $2;
	my $rhs = $3;
	my $meta = $4;
	$rhs =~ s/\\040/ /g;
	$record = "'$lhs:$rhs:$meta";
#	print STDERR "lhs=$lhs length=$length rhs=$rhs meta=$meta\n";
    }
    $md5->add("$record\n");
    print OF "$record\n";
}

my $zonesig = $md5->hexdigest;

print OF "'$sigrecord:$zonesig:60\n";

close OF;

my @args = ('tinydns-data');

unless(system(@args) == 0) {
    print STDERR "Failed to run '@args': $?\n";
    if ($? == -1) {
	print "failed to execute: $!\n";
    }
    elsif ($? & 127) {
	printf "child died with signal %d, %s coredump\n",
	($? & 127),  ($? & 128) ? 'with' : 'without';
    }
    else {
	printf "child exited with value %d\n", $? >> 8;
    }
    die "Giving up\n";
}

foreach my $server (@slaves) {
    my $sig = getsig($server);
    if($sig ne $zonesig) {
	print "Updating $server\n";
	my @args = ('scp', 'data.cdb', "$server:/etc/tinydns/root/data.cdb");
	unless(system(@args) == 0) {
	    print STDERR "Failed to run '@args': $?\n";
	    if ($? == -1) {
		print "failed to execute: $!\n";
	    }
	    elsif ($? & 127) {
		printf "child died with signal %d, %s coredump\n",
		($? & 127),  ($? & 128) ? 'with' : 'without';
	    }
	    else {
		printf "child exited with value %d\n", $? >> 8;
	    }
	    die "Giving up\n";
	}
	my $newsig = getsig($server);
	if($newsig ne $zonesig) {
	    warn "Failed to update $server: $newsig:$zonesig\n";
	}
    }
}

sub getsig($ )
{
    my ($server) = @_;
    my $res = Net::DNS::Resolver->new( nameservers => [$server], recurse => 0);
    my $packet = $res->query($sigrecord, 'TXT');
    my $sig = 'none';
    if($packet) {
	foreach my $rr (grep { $_->type eq 'TXT' } $packet->answer) {
	    $sig = join('', $rr->char_str_list());
	}
    } else {
	warn "Query to $server failed: ", $res->errorstring, "\n";
    }
    return $sig;
}
