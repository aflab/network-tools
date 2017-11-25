#!/usr/bin/perl 
###############################################################################
#
# a piece of code to parse pcap dump file and make stats packets retransmission
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

use strict;

use Getopt::Long;

use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;

use POSIX qw(strftime);

my $err;

my ( $seq_num, $ack_num, $ack, $psh, $rst, $syn, $fin );
my ( $src_ip, $src_port, $dst_ip, $dst_port, $netmask );


my %retransmission  = ();
my %statistics      = ();


my %OPT = ();

GetOptions(
    'r=s'   => \$OPT{'pcap_dump'},
    'f=s'   => \$OPT{'pcap_filter'},
);

&usage() unless defined $OPT{'pcap_dump'};

my $object = Net::Pcap::open_offline($OPT{'pcap_dump'}, \$err);

unless ( defined $object )
{
    die "Can't open $OPT{'pcap_dump'} : $err";
}

my $filter;
Net::Pcap::compile(
    $object,
    \$filter,
    $OPT{'pcap_filter'},
    0,
    $netmask
) && die 'Unable to compile packet capture filter';

Net::Pcap::setfilter($object, $filter)
&& die 'Unable to set packet capture filter';

Net::Pcap::loop($object, -1, \&packets, '');

Net::Pcap::close($object);

&statistics();


sub packets 
{
    my ($data, $header, $packet) = @_;

    my $ether_data = NetPacket::Ethernet::strip($packet);

    my $ip  = NetPacket::IP->decode($ether_data);
    my $tcp = NetPacket::TCP->decode($ip->{'data'});

    $src_ip   = $ip->{'src_ip'};
    $dst_ip   = $ip->{'dest_ip'};
    $src_port = $tcp->{'src_port'};
    $dst_port = $tcp->{'dest_port'};
    $seq_num  = $tcp->{'seqnum'} ? $tcp->{'seqnum'} : 0;
    $ack_num  = $tcp->{'acknum'} ? $tcp->{'acknum'} : 0;

    $ack = ( $tcp->{'flags'}&ACK ) ? 1 : 0;
    $psh = ( $tcp->{'flags'}&PSH ) ? 1 : 0;
    $rst = ( $tcp->{'flags'}&RST ) ? 1 : 0;
    $syn = ( $tcp->{'flags'}&SYN ) ? 1 : 0;
    $fin = ( $tcp->{'flags'}&FIN ) ? 1 : 0;

    return if( $ack && !$psh &&!$rst &&!$syn &&!$fin && ( length($tcp->{'data'})==6 ) );

    my $key = sprintf(
            "%s/%d/%s/%d/%d%d%d%d%d/%.f/%.f",
            $src_ip, $src_port, $dst_ip, $dst_port,
            $ack, $psh, $rst, $syn, $fin,
            $seq_num, $ack_num
        );

    my $day = strftime "%Y/%m/%d", localtime( $header->{'tv_sec'} );

    $statistics{'date'}{$day}{'total'}++;

    if( $retransmission{$key} )
    {
        $statistics{'syn'}++ if $syn;
        $statistics{'fin'}++ if $fin;
        $statistics{'other'}++ if !$syn && !$fin;
        $statistics{'date'}{$day}{'retransmission'}++;
        $statistics{'retransmission'}++;
        my $dhms = strftime "%Y/%m/%d %H:%M:%S", localtime($header->{'tv_sec'});

        printf(
            "RETR [%18s] %d.%-7s %s.%-7s : %s\n", $retransmission{$key},
            $header->{'tv_sec'}, $header->{'tv_usec'},
            $dhms, $header->{'tv_usec'}, $key
        );

    }
    else
    {
        $retransmission{$key} = $header->{'tv_sec'}.".".$header->{'tv_usec'};
    }

    $statistics{'total'}++;
}

sub statistics()
{

    printf( "\nNumber of packets            : %d\n", $statistics{'total'} );
    printf(
        "Number of packets retransmitted    : %d ( %.2f % )\n\n",
        $statistics{'retransmission'},  $statistics{'retransmission'} /  $statistics{'total'} * 100
    );


    foreach ( keys %{$statistics{'date'}} )
    {
        printf(
            "\t%s : %d packets %d packets restransmitted ( %.2f % )\n",
            $_, $statistics{'date'}{$_}{'total'}, $statistics{'date'}{$_}{'retransmission'},
            $statistics{'date'}{$_}{'retransmission'} / $statistics{'date'}{$_}{'total'} * 100
        );
    }
    print "\n";
    printf("Packets with flag syn retransmitted     : %d\n", $statistics{'syn'}     );
    printf("Packets with flag fin retransmitted     : %d\n", $statistics{'fin'}     );
    printf("Packets with other flags retransmitted  : %d\n", $statistics{'other'}   );
}

sub usage()
{
    print "\nUsage :\n\n";
    print "\t$0 -r <pcap dump> [ -f <pcap filter> ]\n\n";
    exit;
}

