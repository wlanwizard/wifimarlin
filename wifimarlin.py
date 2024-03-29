import pyshark
import networkx as nx
import matplotlib.pyplot as plt

def is_data_frame(packet):
    # Function to check if a given packet is an 802.11 data frame.
    # This check is based on the presence of wlan.sa and wlan.da fields in PyShark.
    try:
        # Attempt to access the wlan layer and its sa and da fields
        src = packet.wlan.sa
        dst = packet.wlan.da
        return True
    except AttributeError:
        # If the attributes are not found, it's not a data frame we're interested in
        return False

def parse_pcap(file_path):
    cap = pyshark.FileCapture(file_path, display_filter="wlan")
    comm_dict = {}

    for packet in cap:
        if is_data_frame(packet):
            src = packet.wlan.sa
            dst = packet.wlan.da

            if src and dst:
                if src not in comm_dict:
                    comm_dict[src] = {}
                if dst not in comm_dict[src]:
                    comm_dict[src][dst] = 0
                comm_dict[src][dst] += 1

    cap.close()
    return comm_dict

def generate_graph(comm_dict):
    G = nx.DiGraph()

    for src, dsts in comm_dict.items():
        for dst, weight in dsts.items():
            G.add_edge(src, dst, weight=weight)

    pos = nx.spring_layout(G)
    nx.draw(G, pos, with_labels=True, node_color='skyblue', node_size=700, edge_color='k', linewidths=1, font_size=10, arrows=True, arrowstyle='->', arrowsize=10)
    
    # Draw edge labels to show the weight (count of frames) on each edge
    edge_labels = dict([((u, v,), d['weight']) for u, v, d in G.edges(data=True)])
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title('802.11 Data Frame Communications')
    plt.axis('off')
    plt.show()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python wifimarlin.py <path_to_pcap_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    comm_dict = parse_pcap(file_path)
    generate_graph(comm_dict)
