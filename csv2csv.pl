#! /usr/bin/perl

############################################
# csv2csv.pl v1.0
# 
# Chase Miller (cnmiller@andrew.cmu.edu)              
# 14-832 - Cyber Forensics Capstone
#                               
# Simple perl script to parse a CSV 
# into CSV with conversions for statistical 
# analysis. I'm sure this can be optimized.
############################################


#Accept 2 arguments for infile.log and outfile.csv
my $num_args=$#ARGV+1;
if ($num_args !=2) {
	print "Usage: logs2csv.pl infile.log outfile.csv\n";
	exit;
}

#Assign ARGVs to scalars
my $infile=$ARGV[0];
my $outfile=$ARGV[1];

#Open infile.log and create outfile.csv
open (FILE, "< $infile") or die $!;
open (NEW_FILE, "> $outfile") or die$!;

#Print column headers
print NEW_FILE ('Source,','Destination,','Proto','Length,','Src Port,','Dst Port,','Window Size',"\n");

while (<FILE>) {

	#Do some string matching to identifiy fields from infile.log
	/(\S*),(\S*),(\S*),(\S*),(\S*),(\S*),(\S*)/; 

	$convertedsrc=ip2dec($1);
	$converteddst=ip2dec($2);
	$scaledconvertedsrc=($convertedsrc*.0000002);
	$scaledconverteddst=($converteddst*.0000002);
	if ($3 eq 'TCP'){$proto=6;}
	elsif ($3 eq 'ICMP'){$proto=1}
	elsif ($3 eq 'UDP'){$proto=17}
	else {$proto=0;}

	#Print values to outfile.csv in csv format
	print NEW_FILE "$scaledconvertedsrc,$scaledconverteddst,$proto,$4,$5,$6,$7\n" unless $scaledconvertedsrc eq /^$/ or $scaledconverteddst eq /^$/ or $proto eq /^$/ or $4 eq /^$/ or $5 eq /^$/ or $6 eq /^$/ or $7 eq /^$/;

#ip2dec sub is used to convert the dotted IP address to a decimal IP
	sub ip2dec ($) {
	unpack N => pack CCCC => split /\./ => shift;
	}
}
close FILE;
close NEW_FILE;
