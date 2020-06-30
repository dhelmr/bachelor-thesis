from dataset_utils import pcap_utils




if __name__ == '__main__':
    FILE = "data/ids2017-small/PCAPs/Wednesday-WorkingHours.pcap"

    packets = pcap_utils.read_pcap_pcapng(FILE)
    flow_gen = NetFlowGenerator()
    for packet in packets:
        flow_gen.feed_packet(packet)

    flow_gen.close_all()
    print(flow_gen.flows)




