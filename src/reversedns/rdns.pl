#!/usr/bin/perl

use strict;
use DBI;

my $ttl = '3600';

my $dbh = DBI->connect("dbi:Pg:dbname=powerdns", 'pdns', '', {AutoCommit => 0, RaiseError => 1});

my @zones = @ARGV;

eval {
    my $domh = $dbh->prepare("select id, name from domains");
    $domh->execute();
    
    my %dom;
    my %rdom;

    my @pzones;
    
    while(my ($i, $d) = $domh->fetchrow_array) {
	$dom{$d} = $i;
	if($d =~ /in-addr\.arpa$/) {
	    if($d =~ /^\d+[\/-]\d+\.(\d+\.\d+\.\d+)\.in-addr\.arpa$/) {
		$rdom{$1} = $d;
	    } elsif($d =~ /^subnet\d+\.(\d+\.\d+\.\d+)\.in-addr\.arpa$/) {
		$rdom{$1} = $d;
	    }
	} else {
	    push @pzones, $d;
	}
    }

    @zones = @pzones unless scalar @zones;
    
    my $ptrh = $dbh->prepare("select content, domain_id from records where type='PTR' and name = ?");
    
    foreach my $zone (@zones) {
	die "Zone '$zone' not found\n" unless exists $dom{$zone};
	my $zoneid = $dom{$zone};
	
	my $ah = $dbh->prepare("select name, content from records where domain_id = ? and type = 'A'");
	$ah->execute($zoneid);
	while(my ($a, $ip) = $ah->fetchrow_array) {
	    die "Bad A record for '$a': '$ip'\n" unless $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
	    my ($o1, $o2, $o3, $o4) = ($1, $2, $3, $4);
	    my $inaddr = "$4.$3.$2.$1.in-addr.arpa";

	    my $revid;
	    my $rec = $inaddr;
	    if(exists $rdom{"$o3.$o2.$o1"}) {
		my $rdomain = $rdom{"$o3.$o2.$o1"};
		$revid = $dom{$rdomain};
		$rec = "$4.$rdomain";
	    } elsif(exists $dom{"$o4.$o3.$o2.$o1.in-addr.arpa"}) {
		$revid = $dom{"$o4.$o3.$o2.$o1.in-addr.arpa"};
	    } elsif(exists $dom{"$o3.$o2.$o1.in-addr.arpa"}) {
		$revid = $dom{"$o3.$o2.$o1.in-addr.arpa"};
	    } elsif(exists $dom{"$o2.$o1.in-addr.arpa"}) {
		$revid = $dom{"$o2.$o1.in-addr.arpa"};
	    } elsif(exists $dom{"$o1.in-addr.arpa"}) {
		$revid = $dom{"$o1.in-addr.arpa"};
	    }
	    
	    $ptrh->execute($rec);
	    my $nfound=0;
	    my $matched=0;
	    while(my ($rev, $revid) = $ptrh->fetchrow_array) {
		$nfound++;
		$matched++ if $rev eq $a;
	    }

	    unless($nfound) {
		# insert
		if(defined $revid) {
		    print STDERR "Adding $a -> $rec\n";
		    $dbh->do("insert into records (domain_id, name, type, content, ttl, prio) values (?, ?, 'PTR', ?, $ttl, 0)", {}, $revid, $rec, $a);
		}
	    }
	}
    }
#    die "Just testing\n";
    $dbh->commit;
    $dbh->disconnect;
};

if($@) {
    print STDERR "Failed: $@\n";
    $dbh->rollback;
    $dbh->disconnect;
    die "Giving up\n";
}
