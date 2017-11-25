#!/usr/bin/perl
###############################################################################
#
# Get some stats about time to fetch a web page
#
# License :
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
###############################################################################

use LWP::UserAgent;
use LWP::Protocol;
use LWPx::TimedHTTP;

LWP::Protocol::implementor('http',  'LWPx::TimedHTTP');
LWP::Protocol::implementor('https', 'LWPx::TimedHTTP::https');

&usage() unless $ARGV[0];

my $url = $ARGV[0];
my $total_time = 0;

my $ua = new LWP::UserAgent;

my $response = $ua->get($url);

$total_time  = $response->header('Client-Request-Connect-Time');
$total_time += $response->header('Client-Request-Transmit-Time');
$total_time += $response->header('Client-Response-Server-Time');
$total_time += $response->header('Client-Response-Receive-Time');

my $response_length = length($response->content);
my $download_speed  = ( $response_length / $total_time ) / 1000 ;

print "\n------------\n\n";
printf "URL            : %s\n", $url;
printf "Response       : %s\n", $response->status_line;
printf "Content-length : %d\n", $response_length;
printf "Download speed : %.2f KB/s\n", $download_speed ;
printf "Total time     : %f\n", $total_time;
printf "Connect time   : %f\n", $response->header('Client-Request-Connect-Time');
printf "Transmit time  : %f\n", $response->header('Client-Request-Transmit-Time');
printf "Respons time   : %f\n", $response->header('Client-Response-Server-Time');
printf "Receive time   : %f\n", $response->header('Client-Response-Receive-Time');
print "\n------------\n\n";

sub usage()
{
    print "Usage: \n\n";
    print "\t$0 <url>\n\n";
    exit;
}
