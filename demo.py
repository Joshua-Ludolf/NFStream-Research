""" 
    * Name: Joshua Ludolf & Matthew Trevino
    * Date: 01-29-2025
    * Description: This script demonstrates how to use the NFStreamer class to read a pcap file and print the flows using NFStream.
"""

from nfstream import NFStreamer
import os

def main():
    pcap_file = os.path.join(os.getcwd(), "demo.pcap")

    if not os.path.isfile(pcap_file):
        raise FileNotFoundError(f"The file {pcap_file} does not exist.")

    my_streamer = NFStreamer(source=pcap_file,
                             decode_tunnels=True,
                             bpf_filter=None,
                             promiscuous_mode=True,
                             snapshot_length=1093,
                             idle_timeout=120,
                             active_timeout=1800,
                             accounting_mode=0,
                             udps=None,
                             n_dissections=20,
                             statistical_analysis=False,
                             splt_analysis=0,
                             n_meters=0,
                             max_nflows=0,
                             performance_report=0,
                             system_visibility_mode=0,
                             system_visibility_poll_ms=100)

    for flow in my_streamer:
        print(flow) # print the flow

    my_dataframe = my_streamer.to_pandas(columns_to_anonymize=[]) # convert the flows to a pandas dataframe
    print(f"\n{my_dataframe}") # print the dataframe

    total_flows_count = my_streamer.to_csv(path=None, columns_to_anonymize=[], flows_per_file=0, rotate_files=0) # convert the flows to a csv file

if __name__ == '__main__':
    main()