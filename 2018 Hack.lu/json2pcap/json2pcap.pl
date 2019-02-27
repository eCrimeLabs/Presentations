#!/usr/bin/perl
# * ----------------------------------------------------------------------------
# * "THE BEER-WARE LICENSE":
# * <rand[@]ecrime[.]dk> wrote this code. As long as you retain this notice you
# * can do whatever you want with this stuff. If we meet some day, and you think
# * this stuff is worth it, you can buy me a beer in return Dennis Rand
# * ----------------------------------------------------------------------------
# 
# This code converts a DDoS research project from JSON to a PCAP.
# 
# Usage: perl json2pcap.pl <filename.json>
# https://www.ecrimelabs.com  

use strict;
use JSON -support_by_pp;
use Net::PcapWriter;
use File::Slurp;
use MIME::Base64;
use Digest::MD5 qw(md5 md5_hex md5_base64);

my $input_file = $ARGV[0];
unless (-e $input_file) { print "No such file\r\n"; exit; }
my $content = read_file($input_file);
my $digest  = md5_hex($content);
my $json    = new JSON;

print "Parsing JSON file with: ";
my $json_text = $json->allow_nonref->utf8->relaxed->escape_slash->loose->allow_singlequote->allow_barekey->decode($content);
my $minimum = 1025;
my $maximum = 65000;
my $request_response_num = 1;
my $min_amp_factor = 0; # If only want to create PCAP with service with an amplification capabilities set value = 2

my $attack_type = $json_text->{base}->{attack_type};
   $attack_type =~ s/\s/_/g;
my $lines = $json_text->{base}->{data_entries};
print "$lines \r\n";
my $dst_port = $json_text->{base}->{port};
my $output_file = $digest . "_" . $attack_type . '.pcap';

# disabling checksum calculation leads to huge performance boost
Net::PcapWriter::IP->calculate_checksums(0);
my $writer = Net::PcapWriter->new($output_file);

print "Start writing pcap -> $output_file \r\n";
foreach my $reqresp(@{$json_text->{data}}){
   my $dst_ip = $reqresp->{soldier};
   my $amp_factor = $reqresp->{amp_factor};
   unless ($amp_factor > $min_amp_factor) { next; }
      
   my $src_port = $minimum + int(rand($maximum - $minimum));
   my $request = decode_base64($reqresp->{sent_data});
   my $response = decode_base64($reqresp->{recvd_data});

   # write some UDP packets with IPv4
   my $conn = $writer->udp_conn('100.64.0.1',$src_port,$dst_ip,$dst_port);
   $conn->write(0,$request);
   $conn->write(1,$response);
   $request_response_num++;
}

# catch crashes:
if($@){
   print "[[JSON ERROR]] JSON parser crashed! $@\n";
} 
