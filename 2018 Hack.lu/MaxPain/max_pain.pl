#!/usr/bin/env perl
# * ----------------------------------------------------------------------------
# * "THE BEER-WARE LICENSE":
# * <rand[@]ecrime[.]dk> wrote this code. As long as you retain this notice you
# * can do whatever you want with this stuff. If we meet some day, and you think
# * this stuff is worth it, you can buy me a beer in return Dennis Rand
# * ----------------------------------------------------------------------------
#
# Proof-of-Concept code to extract potential vulnerable systems based on tiers
#
# Usage: perl max_pain.pl --help

# https://www.ecrimelabs.com

use strict;
use Net::IP;
use Net::CIDR;
use Net::CIDR ':all';
use Net::DNS;
use Geo::IP;
use Data::Dumper qw(Dumper);
use JSON -support_by_pp;
use Getopt::Long;
use Search::Elasticsearch;
use LWP::UserAgent;
use HTTP::Request::Common qw(GET);

my $target;
my $local_range = 24; # /24 Range and above
my $gt_days     = 30; # Used with ElasticSearch
my $gbit2byte   = 134217728; # bytes = 1Gbit (http://www.matisse.net/bitcalc/?input_amount=1&input_units=gigabits&notation=legacy)
my $gte_amp     = 2;
my $reqsec      = 25;
my $udp_header  = 46;
my $max         = 6; # Max amount of Tiers avaliable
my $sort        = 'recv_bytes';
my $tier_min    = 1;
my $tier_max    = 4;

my $debug;
my $simulate;
my $verbose;
my $anon;
my $help;

my %osint;
my %tier_summary;
my @elk_arr;

GetOptions(
    'cidr=i'     => \$local_range,
    'days=i'     => \$gt_days,
    'amp=i'      => \$gte_amp,
    'sec=i'      => \$reqsec,
    'target=s'   => \$target,
    'tier_min=i' => \$tier_min,
    'tier_max=i' => \$tier_max,
    'debug'      => \$debug,
    'verbose'    => \$verbose,
    'simulate'   => \$simulate,
    'anon'       => \$anon,
    'help!'      => sub { usage(0) },
) or usage(1);

sub usage {
   splash_screen();
   print "\r\n";
   print " ====================== USAGE ========================\r\n";
   print "\t--target 127.0.0.1 (Target IP to analyze) \r\n";
   print "\t--cidr $local_range (Below CIDR Range for Tier 1 search)\r\n";
   print "\t--days $gt_days (Amount of days to seach back in ELK)\r\n";
   print "\t--amp $gte_amp (Minimal amplification factor required)\r\n";
   print "\t--sec $reqsec (Expected average requests per second to send out)\r\n";
   print "\t--tier_min $tier_min \r\n";
   print "\t--tier_max $tier_max \r\n";
   print "\t--sort $sort (amp_factor or recv_bytes)\r\n";
   print "\r\n";
   print "\t--debug (Show Debug mode)\r\n";
   print "\t--simulate (Don't query Elastic)\r\n";
   print "\t--anon (Anonymize threat report)\r\n\r\n";
   print "\t===============================\r\n";
   print "\tTIER Description:\r\n";
   print "\tTier 1 - Is systems within a $local_range CIDR of target\r\n";
   print "\tTier 2 - checks systems within annonced CIDR of target\r\n";
   print "\tTier 3 - Systems within AS number detected for IP\r\n";
   print "\tTier 4 - Upstream Peering partners of tier 3 AS\r\n";
   print "\tTier 5 - Systems within the same Country as the IP\r\n";
   print "\tTier 6 - Systems outside of country related to IP\r\n";
   print " =====================================================\r\n\r\n\r\n";
   exit;
}


sub splash_screen {
   my $version = "1.1 (Elastic 6.x)";
   print "\r\n";
   print "\t     Max Pain v.$version\r\n";
   print qq(               `:+ydNNNNNds`
             :yNMMMMMMMMMMMNd/
           -dMMMMMMMMMMNhssNMh
           :NMMMMMMMms:`   :Mm
            /MMMMMMMd-     `+N+`
            `:NMMMMN/:../sdd-yd:
              -NMMMMNMN./ss. `h-
               +NMMMMMMo  --  +`
      /+`       +NMMmMMNd/`.
     sMMs        -+NMMMMNh+-  o/: ..
     `mMMs`        /NMMMMm/ -yMNdhmNy:
      -mMMy`        -odMMmyhNMmdNMMMMNo:--.`
      `+MMMd:         `hMMMMMhmNMMMMMMMMNNmmho-
      o/NMMMN/         -MMNNMNMMMMMMMMMMMMMMMMNy.
      .mMMMMMN+`      .ohosmMMMMMMMMMMMMMMMMMMMMN/
     `+hNMMMMMM/     :m-`o/NMMMMMMMMMMMMMMMMMMMMMN
    .--/mMMMMM/.   `oNm    -dMMMMMMMMMMMMMMMMMMMMM
    dhyhMMMMNo`   -dMMh  `./dMMMMMMMMMMMMMMMMMMMMM
    +MMMMMMMy   `omMMMy:shNMMMMMMMMMMMMMMMMMMMMMMM
    +NMMMMMMd  .hNNMMMdMMNMMMMMMMMMMMMMMMMMMMMMMMM
   /MMNMMMMMM--dMmMMMN`yMMMMMMMMMMMMMMMMMMMMMMMMMM
   oMMMMMMMMM+mNMMMMMd `dMMMMMMMMMMMMMMMMMMMMMMMMM
   .NMMMMMMMMdNMMMMMMh  .NMMMMMMMMMMMMMMMMMMMMMMMM
    oMMMMMMMMmNMMMMMMy   +MMMMMMMMMMMMMMMMMMMMMMMM
     hMMMMMMNMMMMMMMMM-  `MMMMMMMMMMMMMMMMMMMMMMMM
     `dMMMMMNmNMMMMMMM:   NMMMMMMMMMMMMMMMMMMMMMMM
      `dMMMMddmMMMMMMN`   NMMMMMMMMMMMMMMMMMMMMMMM
       `dMMMMdmMMMMMMo   `MMMMMMMMMMMMMMMMMMMMMMMM
        `hMMMNMMMMMMMo   .MMMMMMMMMMMMMMMMMMMMMMMM
         `yMMMMMMMMMMy   .MMMMMMMMMMMMMMMMMMMMMMMM
           /mMMMMMMMMN`  `MMMMMMMMMMMMMMMMMMMMMMMM
            :MMMMMMMMM/   m (c)2018 Dennis Rand MM
             :MMMMMMMM.   MMMMMMMMMMMMMMMMMMMMMMMM
   );
   print "\r\n -----------------------------------------------------\r\n";
}

sub ElasticSearchGetData {
   my $tier        = shift;
   my $elk_header  = '{"size": 0,"aggregations": {"group": {"terms": {"field": "dst_ip","order": {"avg_balance": "desc"}},"aggs": {"group_docs": {"top_hits": {"size": 1}},"avg_balance": {"avg": {"field": "recv_bytes"}}}}},"query":{"bool":{"must":[';
   my $elk_header1 = '{"size": 0,"aggregations": {"group": {"terms": {"field": "dst_ip","order": {"avg_balance": "desc"}},"aggs": {"group_docs": {"top_hits": {"size": 1}},"avg_balance": {"avg": {"field": "recv_bytes"}}}}},"query":{"bool":{"must_not":[';

   my $elk_footer  = '],"filter":[{"range":{"amp_factor":{"gte":"' . $gte_amp . '"}}},{"range":{' . "" . '"@timestamp"' . "" . ':{"gte":"now-' . $gt_days . 'd","lte":"now"}}}]}}}';
   my $elk_proto   = '';
   my $query       = undef;
   my $es = Search::Elasticsearch->new( nodes => ['192.168.1.13:9200'], request_timeout => 600);
   if ($tier == 0){

   } elsif ($tier == 1){ ################################ TIER 1
      # For Tier 1 - Remove the amp_factor part
      $elk_footer =~ s/amp_factor":\{"gte":"([0-9]{1,})"/amp_factor":\{"gte":"1"/smxg;

      if($debug){ print "Searching for Tier 1 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier1"} } ) {
         my $match  = '{"match":{"dst_ip":"' . $key . '"}}';
         my $output = '';
         my $full_query = $elk_header . $match . $elk_footer;

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"_doc",/"_tier":"1",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"1"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } elsif ($tier == 2){ ################################ TIER 2
      # For Tier 2 - Remove the amp_factor part
      $elk_footer =~ s/amp_factor":\{"gte":"([0-9]{1,})"/amp_factor":\{"gte":"1"/smxg;

      if($debug){ print "Searching Tier 2 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier2"} } ) {
         my $match  = '{"match":{"dst_ip":"' . $key . '"}}';
         my $output = '';
         my $full_query = $elk_header . $match . $elk_footer;

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"doc",/"_tier":"2",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"2"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } elsif ($tier == 3){ ################################ TIER 3
      # For Tier 3 - Remove the amp_factor part
      $elk_footer =~ s/amp_factor":\{"gte":"([0-9]{1,})"/amp_factor":\{"gte":"1"/smxg;

      if($debug){ print "Searching Tier 3 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier3"} } ) {
         $key =~ s/AS//;
         my $match  = '{"match":{"dst_whois.asn.raw":"' . $key . '"}}';
         my $output = '';
         my $full_query = $elk_header . $match . $elk_footer;

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"_doc",/"_tier":"3",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"3"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } elsif ($tier == 4){ ################################ TIER 4 <<
      if($debug){ print "Searching Tier 4 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier4"} } ) {
         $key =~ s/AS//;
         my $match  = '{"match":{"dst_whois.asn.raw":"' . $key . '"}}';
         my $output = '';
         my $full_query = $elk_header . $match . $elk_footer;

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"_doc",/"_tier":"4",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"4"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } elsif ($tier == 5){ ################################ TIER 5
      if($debug){ print "Searching Tier 5 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier5"} } ) {
         my $match   = '{"match":{"dst_geoip.country_code2":"' . $key . '"}}';
         my $output  = '';
         my $full_query = $elk_header . $match . $elk_footer;

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"_doc",/"_tier":"5",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"5"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } elsif ($tier == 6){ ################################ TIER 6
      if($debug){ print "Searching Tier 6 systems\r\n"; }
      while (my ($key, $value) = each %{ $osint{"tier5"} } ) {
         my $match   = '{"match":{"dst_geoip.country_code2":"' . $key . '"}}';
         my $output  = '';
         my $full_query = $elk_header1 . $match . $elk_footer; # Uses the elk_header1

         if($debug){ print $full_query . "\r\n"; }

         my $scroll = $es->scroll_helper(index => 'dadosmon_2018',body  => $full_query, size => 100);
         $output = '{"hits":[';
         while (my $doc = $scroll->next){
            my $json_str = encode_json($doc);
            $output .= "," . $json_str;
         }
         $output .= "]}";
         $output =~ s/\[,/\[/;
         $output =~ s/"_type":"_doc",/"_tier":"6",/g;
         $output =~ s/"_type"/"_tier"/g;
         $output =~ s/"event"/"6"/g;
         push (@elk_arr, $output);
         # -------------------------
      }
   } else {}
}

sub ElasticSearchParser {
   my $cnt_recv_bytes = 0;
   my $cnt_sent_bytes = 0;
   my %data_loop;
   my %tier_data;
   my %protocols;
   my %tier_data;

   ### Add data data from JSON into multidimentional hash
   foreach my $result (@elk_arr){
      my $json    = new JSON;
      my $num = 1;
      my $json_text = $json->decode($result);

      foreach my $data_loop(@{$json_text->{hits}}){
         my $ip          = $data_loop->{_source}{dst_ip};
         my $port        = $data_loop->{_source}{dst_port};
         my $proto       = $data_loop->{_source}{proto};
         my $attack_desc = $data_loop->{_source}{attack_desc};
         my $sent_bytes  = $data_loop->{_source}{sent_bytes};
         my $recv_bytes  = $data_loop->{_source}{recv_bytes};
         my $amp_factor  = $data_loop->{_source}{amp_factor};
         my $tier_num    = $data_loop->{_tier};

         if(exists $tier_data{"ip"}{$ip}{"port"}{$port}{"attack_desc"}{$attack_desc}){
            next;
         } else {
            $cnt_recv_bytes = $cnt_recv_bytes + (($recv_bytes + $udp_header)*$reqsec);
            $cnt_sent_bytes = $cnt_sent_bytes + (($sent_bytes + $udp_header)*$reqsec);

            $tier_summary{"tier"}{$tier_num}{"sent_bytes"} = $cnt_sent_bytes;
            $tier_summary{"tier"}{$tier_num}{"recv_bytes"} = $cnt_recv_bytes;
            $tier_summary{"tier"}{$tier_num}{"sent"} = ConvertBytes($cnt_sent_bytes);
            $tier_summary{"tier"}{$tier_num}{"recv"} = ConvertBytes($cnt_recv_bytes);
            $tier_summary{"tier"}{$tier_num}{"hosts"} = $num++;
            $tier_summary{"tier"}{$tier_num}{"proto"}{$proto}{"hosts"} = $tier_summary{"tier"}{$tier_num}{"proto"}{$proto}{"hosts"} + 1;
            $tier_summary{"tier"}{$tier_num}{"attack_desc"}{$attack_desc}{"hosts"} = $tier_summary{"tier"}{$tier_num}{"attack_desc"}{$attack_desc}{"hosts"} + 1;
            $tier_summary{"tier"}{$tier_num}{"proto"}{$proto}{"percentage"} = two_decimals((($tier_summary{"tier"}{$tier_num}{"proto"}{$proto}{"hosts"}) / $num)*100);
            $tier_summary{"tier"}{$tier_num}{"attack_desc"}{$attack_desc}{"percentage"} = two_decimals((($tier_summary{"tier"}{$tier_num}{"attack_desc"}{$attack_desc}{"hosts"}) / $num)*100);

            # The following is ONLY to ensure that if the same IP, port, protocol and attack pattern comes up it will not count twice
            $tier_data{"ip"}{$ip}{"port"}{$port}{"attack_desc"}{$attack_desc}{"tier"} = $tier_num;
         }
      }
   }
}


################################## Below is OSINT ##################################
sub ValidateIP {
   my $ip = shift;
   if ($ip =~ m/(^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)/){
      return(1)
   } else {
      return(0);
   }
}

sub Peering_upstream {
   my $asn = shift;
   my $ua = LWP::UserAgent->new;
   my $content = undef;
   $ua->agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36');
   my $req = GET 'http://www.cidr-report.org/cgi-bin/as-report?as=' . $asn;
   my $res = $ua->request($req);
   my $num = 1;

   # Check the response
   if ($res->is_success) {
       $content = $res->content;
       my $upstream = undef;
       if ($content =~ m/Upstream\sAdjacent\sAS\slist.*?(Downstream\sAdjacent\sAS\slist|Announced\sPrefixes)/smx) {
          $upstream= $&;
       }
       my @results = $upstream =~ m!<a\shref="/cgi-bin/as-report\?as=(AS[0-9]{1,8})&v=4!smxg;
       foreach my $result (@results){
          $osint{"tier4"}{$result} = $result;
       }
   } else {
       print "ERROR Peering_upstream\r\n";
       print $res->status_line . "\n";
       exit;
   }
}

sub WhoisMadness {
   my $ip         = shift;
   my $ip_start1  = undef;
   my $ip_end1    = undef;
   my @cidrs1;
   my $cmd1       = `whois -b $ip 2>&1`;

   my $ip_start2  = undef;
   my $ip_end2    = undef;
   my @cidrs2;
   my $cmd2       = `whois $ip 2>&1`;

   if ($cmd2 =~ m/Joint\sWhois\s-\swhois.lacnic.net.*?inetnum:\s+/smx) {
      # lacnic.net acting weird
      if ($cmd2 =~ m!(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b\/[1-9]?[0-9])!) {
         my $cidr2 = $1;
         push(@cidrs2, $cidr2);
         my @tmps = Net::CIDR::cidr2range($cidr2);
         foreach my $tmp (@tmps){
            ($ip_start2,$ip_end2) = split('-', $tmp);
         }
         return($ip_start2, $ip_end2, @cidrs2);
      }
   }

   if ($cmd1 =~ m/(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)\s-\s(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)/) {
      $ip_start1 = $1;
      $ip_end1   = $6;
      @cidrs1 = Net::CIDR::range2cidr("$ip_start1-$ip_end1");
   } else {

   }
   if ($cmd2 =~ m/(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)\s-\s(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b)/) {
      $ip_start2 = $1;
      $ip_end2   = $6;
      @cidrs2 = Net::CIDR::range2cidr("$ip_start2-$ip_end2");
   } else {

   }
   my $num1 = @cidrs1;
   my $num2 = @cidrs2;

   if ($num1 >= $num2){
      return($ip_start2, $ip_end2, @cidrs2);
   } else {
      return($ip_start1, $ip_end1, @cidrs1);
   }
}

sub WhoisScrapper {
   my $ip         = shift;
   my $cidr       = undef;
   my $reverse_ip = undef;
   my $gi_asn = Geo::IP->open( "./GeoIPASNum.dat", GEOIP_STANDARD );
   my $gi = Geo::IP->open("./GeoIP.dat", GEOIP_STANDARD);

   my $num = 1;

   my ($ip_start, $ip_end, @cidrs) = WhoisMadness($ip);
   my $ipobj = new Net::IP ($ip) or die (Net::IP::Error());
   $reverse_ip = $ipobj->reverse_ip();
   $reverse_ip =~ s/\.in-addr\.arpa\.//;

   $osint{"_target"} = $ip;
   $osint{"_range_start"} = $ip_start;
   $osint{"_range_stop"} = $ip_end;

   if ($ip =~ m/(\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.\b)/smx) {
      $cidr  = $1;
      $cidr .= "0/" . $local_range;
      $osint{"tier1"}{$cidr} = $cidr;
   } else {
      print "An Error occoured - Tier 1 search\r\n";
      exit;
   }

   my $asn = $gi_asn->name_by_addr($ip) || '';
   $asn =~ s/(\d+).*$/$1/;
   $osint{"tier3"}{$asn} = $asn;
   Peering_upstream($asn);

   my $country_code2 = $gi->country_code_by_addr($ip) || '';
   $osint{"tier5"}{$country_code2} = $country_code2;
   $osint{"tier6"}{$country_code2} = $country_code2;
   $osint{"reverse"} = $reverse_ip;

   foreach my $cidr (@cidrs){
      $osint{"tier2"}{$cidr} = $cidr;

      my $number = $cidr;
      $number =~ s/.*\///;
      if (($number >= $local_range) && ($number <= 32)) {
         next;
      }
      my $asn = $gi_asn->name_by_addr($cidr) || '';
      $asn =~ s/(\d+).*$/$1/;
      $osint{"tier3"}{$asn} = $asn;
      Peering_upstream($asn);
      my $tmp = $cidr;
      $tmp =~ s/\/.*//;

      my $country_code2 = $gi->country_code_by_addr($tmp) || '';
      $osint{"tier5"}{$country_code2} = $country_code2;
      $osint{"tier6"}{$country_code2} = $country_code2;
   }

   # Searching tier4 for data also in tier3 and delete in tier4
   while (my ($key, $value) = each %{ $osint{"tier3"} } ) {
      if( exists $osint{"tier4"}{$key} ){
         delete $osint{"tier4"}{$key}
      }
   }
}

################################## Below is Reporting ##################################

sub report_header {
   print "\r\n\r\n";
   unless ($anon){
      print " Threat report for " . $osint{"_target"} . "\r\n";
      print " -----------------------------------------------------\r\n";
      print " Estimated responses per second: $reqsec \r\n";
      print " Minimum amplification factor: $gte_amp \r\n\r\n";
      print " Tier 1 - Local CIDR: \r\n";
      while (my ($key, $value) = each %{ $osint{"tier1"} } ) { print "\t - $key \r\n"; }
      print " Tier 2 - Annonced CIDR: \r\n";
      while (my ($key, $value) = each %{ $osint{"tier2"} } ) { print "\t - $key \r\n"; }
      print " Tier 3 - AS Number(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier3"} } ) { print "\t - $key \r\n"; }
      print " Tier 4 - Upstream Peering - AS Number(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier4"} } ) { print "\t - $key \r\n"; }
      print " Tier 5 - Country code(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier5"} } ) { print "\t - $key \r\n"; }
      print " Tier 6 - NOT Country code(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier6"} } ) { print "\t - $key \r\n"; }
      print "\r\n";
   } else {
      my $counter = 0;
      print " Anonymized Threat report\r\n";
      print " -----------------------------------------------------\r\n";
      print " Estimated responses per second: $reqsec \r\n";
      print " Minimum amplification factor: $gte_amp \r\n\r\n";
      print " Tier 1 - Local CIDR: \r\n\t - <REDACTED>/$local_range \r\n";

      print " Tier 2 - Number of Annonced CIDR(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier2"} } ) {
         $key =~ s/\b(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b/<REDACTED>/smxg;
         print "\t - $key \r\n";
      }
      print " Tier 3 - AS Number(s): \r\n";
      $counter = 0;
      while (my ($key, $value) = each %{ $osint{"tier3"} } ) { $counter++; }
      print "\t - $counter ASN(s)\r\n";

      print " Tier 4 - Upstream Peering - AS Number(s): \r\n";
      $counter = 0;
      while (my ($key, $value) = each %{ $osint{"tier4"} } ) { $counter++; }
      print "\t - $counter Upstream Peer(s)\r\n";

      print " Tier 5 - Country code(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier5"} } ) { print "\t - $key \r\n"; }
      print " Tier 6 - NOT Country code(s): \r\n";
      while (my ($key, $value) = each %{ $osint{"tier6"} } ) { print "\t - $key \r\n"; }
      print "\r\n";

   }
}

sub Reporting {
   if ($tier_min == $tier_max){
      print " The report is covering Tier $tier_min \r\n";
   } else {
      print " The report is covering Tiers from $tier_min to $tier_max \r\n";
   }
   print " -----------------------------------------------------\r\n\r\n";
   foreach my $i ($tier_min..$tier_max) {
      my $hosts      = $tier_summary{"tier"}{$i}{"hosts"};
      my $sent       = $tier_summary{"tier"}{$i}{"sent"};
      my $recv       = $tier_summary{"tier"}{$i}{"recv"};
      my $recv_bytes = $tier_summary{"tier"}{$i}{"recv_bytes"};
      my $sent_bytes = $tier_summary{"tier"}{$i}{"sent_bytes"};
      if(length($hosts) < 1){ $hosts = 0; }
      if(length($sent) < 1){ $sent = "0 Kbit/s"; }
      if(length($recv) < 1){ $recv = "0 Kbit/s"; }
      if(length($recv_bytes) < 1){ $recv_bytes = 0; }
      if(length($sent_bytes) < 1){ $sent_bytes = 0; }

      print "\r\n";
      print " Tier $i\r\n";
      print " -------------------------\r\n";
      print " \t - Number of hosts: " . $hosts . "\r\n";
      print " \t - Estimated spoofed sent: " . $sent . "\r\n";
      print " \t - Estimated attack size: " . $recv . "\r\n";
      unless ($recv_bytes == 0 || $sent_bytes == 0){
         print " \t - Summary average amplification factor: ";
         print two_decimals(($recv_bytes / $sent_bytes)) . "\r\n";
      }

      unless ($recv_bytes == 0 || $sent_bytes == 0){
         print "\r\n";
         print " \t Protocol(s) \r\n";
         print " \t-------------------------\r\n";
         while (my ($proto) = each %{ $tier_summary{"tier"}{$i}{"proto"} } ) {
            print "\t  - " . uc($proto);
            print " (" . $tier_summary{"tier"}{$i}{"proto"}{$proto}{"percentage"} . "%)";
            print " (" . $tier_summary{"tier"}{$i}{"proto"}{$proto}{"hosts"} . ")\r\n";
         }

         print "\t\n";
         print " \t Attack Pattern(s) \r\n";
         print " \t-------------------------\r\n";
         while (my ($attack_desc) = each %{ $tier_summary{"tier"}{$i}{"attack_desc"} } ) {
            print "\t  - " . ($attack_desc);
            print " (" . $tier_summary{"tier"}{$i}{"attack_desc"}{$attack_desc}{"percentage"} . "%)";
            print " (" . $tier_summary{"tier"}{$i}{"attack_desc"}{$attack_desc}{"hosts"} . ")\r\n";
         }
      }
      sleep 3;
   }
   if ($debug){
      print Dumper (\%tier_summary);
   }
}

################################## Below is MAIN ##################################
splash_screen();

sub two_decimals {
   my $number = shift;
   return (sprintf "%.2f", $number);
}

sub ConvertBytes
{
   my $bytes = shift;
   my $gbit  = 134217728; # 1 Gbit
   my $mbit  = 131072;    # 1 Mbit
   my $kbit  = 128;       # 1 Kbit

   if($bytes >= $gbit){
      my $sum   = ($bytes / $gbit);
      return (sprintf "%.2f Gbit/s", $sum);
   }
   elsif($bytes < $gbit && $bytes >= $mbit){
      my $sum   = ($bytes / $mbit);
      return (sprintf "%.2f Mbit/s", $sum);
   }
   elsif($bytes < $mbit){
      my $sum   = ($bytes / $kbit);
      return (sprintf "%.2f Kbit/s", $sum);
   }
}

if(ValidateIP($target)){
   WhoisScrapper($target);
} else {
   print "Invalid IP \r\n";
   exit;
}

report_header();
if($simulate){ exit;}
foreach my $i ($tier_min..$tier_max) {
   ElasticSearchGetData($i);
}

ElasticSearchParser();
Reporting();

print "\r\n\r\n";
