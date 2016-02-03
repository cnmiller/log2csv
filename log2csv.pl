#! /usr/bin/perl

############################################
# log2csv.pl v1.0
# 
# Chase Miller (cnmiller@andrew.cmu.edu)              
# 14-832 - Cyber Forensics Capstone
#                               
# Simple perl script to parse iptable logs 
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
print NEW_FILE ('In,','PhysIn,','Out,','PhysOut,','Src,','Dst,','Len,','Tos,','Prec,','TTL,','ID,','Proto,','SPT,','DPT,','Window,','RES',"\n");

while (<FILE>) {

	#Do some string matching to identifiy fields from infile.log
	/IN=(\S*) .*PHYSIN=(\S*) .*OUT=(\S*) .*PHYSOUT=(\S*) .*SRC=(\S*) .*DST=(\S*) .*LEN=(\S*) .*TOS=(\S*) .*PREC=(\S*) .*TTL=(\S*) .*ID=(\S*) .*PROTO=(\S*) .*SPT=(\S*) .*DPT=(\S*) .*WINDOW=(\S*) .*RES=(\S*)/; 
		if ($1 eq 'br0'){
			$in=0;}
			else {
				$in=1;
			}
		if ($2 eq 'eth0'){
			$physin=0;}
			else {
				$physin=1;
			}
		if ($3 eq 'br0'){
			$out=0;}
			else {
				$out=1;
			}
		if ($4 eq 'eth0'){
			$physout=0;}
			else {
				$physout=1;
			}
		$convertedsrc=ip2dec($5);  #Convert dotted source ip to decimal
		$converteddst=ip2dec($6);  #Convert dotted destination ip to decimal
		$scaledconvertedsrc=($convertedsrc*.0000002); #Scaled for statistics purposes - can be improved/adjusted.
		$scaledconverteddst=($converteddst*.0000002); #Scaled for statistics purposes - can be improved/adjusted.
		$length=$7;
		if ($8 eq '0x00'){
			$tos=0;}
			else {
				$tos=1;
			}
		if ($9 eq '0x00'){
			$prec=0;}
			else {
				$prec=1;
			}
		$ttl=$10;
		$id=$11;
		if ($12 eq 'TCP'){
			$protocol=6;}
			else {
				$protocol=17;
			}
		$spt=$13;
		$dpt=$14;
		$window=$15;
		if ($16 eq '0x00'){
			$res=0;}
			else {
				$res=1;
			}
	#Print values to outfile.csv in csv format
	print NEW_FILE "$in,$physin,$out,$physout,$scaledconvertedsrc,$scaledconverteddst,$length,$tos,$prec,$ttl,$id,$protocol,$spt,$dpt,$window,$res\n";

#ip2dec sub is used to convert the dotted IP address to a decimal IP
	sub ip2dec ($) {
	unpack N => pack CCCC => split /\./ => shift;
	}
}
close NEW_FILE;
close FILE;