"""
Description: This Python module parses network traffic data using the nfstream module and creates a CSV file containing various features of the traffic flows.

usage:
python3 nfst_dataset.py traffic.pcap output_file_name

Dependencies:
NFStreamer, inctruction to download: https://www.nfstream.org/docs/
"""

from nfstream import NFStreamer
import csv
import argparse


# create an argument parser
parser = argparse.ArgumentParser(
    description='extract features from pcap file into CSV file')

if __name__ == '__main__':
    # add a positional argument and parse it
    parser.add_argument(
        'file', type=str, help='full location path to the pcap file, example: traffic.pcap ')
    # add a positional argument and parse it
    parser.add_argument(
        'output', type=str, help='name of output file, example: output_file_name')
    args = parser.parse_args()
    input_file = args.file
    output_filename = args.output

    my_streamer = NFStreamer(
        source=input_file,
        bpf_filter="(ip src net 192.168.10.0/24) and (ip dst net 192.168.10.0/24)",
        promiscuous_mode=True,
        idle_timeout=5,
        active_timeout=5,
        accounting_mode=0,
        udps=None,
        n_dissections=1,
        statistical_analysis=True,
        splt_analysis=3,
        n_meters=0,
        max_nflows=2000,
        performance_report=0,
        system_visibility_mode=0,
        system_visibility_poll_ms=1000)

    for flow in my_streamer:
        print(flow)
    total_flows_count = my_streamer.to_csv(
        path="{}.csv".format(output_filename),
        flows_per_file=2000,
        rotate_files=0)
