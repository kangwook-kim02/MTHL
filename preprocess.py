import os
import gzip
import json
import random
from tqdm import tqdm
from scapy.all import PcapReader, IP, TCP, UDP
from sklearn.model_selection import train_test_split

# 경로 설정
dataset_root = "/data/KISTI_DATASETS"  # 데이터셋 경로
output_dir = "./data/KISTI"
os.makedirs(output_dir, exist_ok=True)

# 최대 10개 패킷만 사용해서 특징 추출 --> *나중에 문제 생길 수도 있을 것 같다. (논문에서는 48개 패킷을 사용해서 특징을 추출했기 때문이다.)
# 48개로 세팅할 경우 list records 비어있게 되서 전처리가 진행되지 않는 문제 발생 
# 논문에 써져있는 feature 가져오기
def extract_features_from_pcap(pcap_path, max_packets=10):
    try:
        with PcapReader(pcap_path) as pcap:
            packets = []
            for _ in range(max_packets):
                pkt = pcap.read_packet()
                if pkt is None:
                    break
                if IP in pkt:
                    packets.append(pkt)
    except:
        return None

    if len(packets) < 2:  # 시간 차 계산을 위해 최소 2개
        return None

    lengths = [len(pkt) for pkt in packets]
    proto = packets[0][IP].proto
    src_port, dst_port = 0, 0
    try:
        if proto == 6 and TCP in packets[0]:
            src_port = packets[0][TCP].sport
            dst_port = packets[0][TCP].dport
        elif proto == 17 and UDP in packets[0]:
            src_port = packets[0][UDP].sport
            dst_port = packets[0][UDP].dport
    except:
        pass

    feature = {
        "id": random.randint(1000000, 9999999),
        "time_length": float(packets[-1].time - packets[0].time), # flow 마지막 패킷의 시간 - flow 첫 번째 패킷의 시간
        "bytes_out": sum(lengths),
        "num_pkts_out": len(packets),
        "src_port": src_port,
        "dst_port": dst_port,
        "pr": proto,
        "sa": "IP_masked",
        "da": "IP_masked",
        "pld_mean": sum(lengths) / len(lengths) if lengths else 0,
        "pld_max": max(lengths) if lengths else 0,
        "pld_median": sorted(lengths)[len(lengths)//2] if lengths else 0,
        "hdr_mean": 8.0,
        "hdr_distinct": 1
    }
    return feature

# 폴더명에서 라벨 추론
def infer_labels_from_path(pcap_path):
    # 여기 부분 수정 (labeling 정확하게 하는 법 고안, 일단은 파일명만 보고 판단을 했음)
    # 패킷을 까보고 판단해보는 것도 좋을 거 같음
    top = pcap_path.split("/")[3]
    mid = pcap_path.split("/")[4]
    # category = pcap_path.split("/")[5]  # ex) brute_force_mysql
    fine = "TCP"
    top_label = top
    proto = "TCP" # protocol도 무슨 값인지 정확하게 모르지 않나?
    # app = category.replace("_", "-").capitalize()
    mid_label = mid
    fine_label = fine
    return top_label, mid_label, fine_label

# 전체 pcap 순회 및 전처리
def traverse_and_process_all_pcaps(root_dir):
    records = []
    labels_top, labels_mid, labels_fine = {}, {}, {}

    for normalorattack in tqdm(os.listdir(root_dir)):
        attacktype_dir = os.path.join(root_dir,normalorattack)
        print(attacktype_dir)
        if not os.path.isdir(attacktype_dir):
            continue
        for attack_type in tqdm(os.listdir(attacktype_dir)):
            flows_dir = os.path.join(attacktype_dir, attack_type, "flows")
            if not os.path.isdir(flows_dir):
                continue
            for flow_group in tqdm(os.listdir(flows_dir)):
                group_path = os.path.join(flows_dir, flow_group)
                if not os.path.isdir(group_path):
                    continue
                
                # for file in tqdm(os.listdir(group_path)):
                file = os.listdir(group_path)
                if normalorattack == "normal":
                    for i in range(50): # flow.pcap 파일을 50개까지만
                        fname = file[i]
                        if not fname.endswith(".pcap"):
                            continue
                        pcap_path = os.path.join(group_path, fname)
                        feat = extract_features_from_pcap(pcap_path)
                        if not feat:
                            continue
                        fid = str(feat["id"])
                        top, mid, fine = infer_labels_from_path(pcap_path)
                        labels_top[fid] = top
                        labels_mid[fid] = mid
                        labels_fine[fid] = fine

                        records.append(feat) 
                else:    
                    for i in range(10): # flow.pcap 파일을 10개까지만
                        fname = file[i]
                        if not fname.endswith(".pcap"):
                            continue
                        pcap_path = os.path.join(group_path, fname)
                        feat = extract_features_from_pcap(pcap_path)
                        if not feat:
                            continue
                        fid = str(feat["id"])
                        top, mid, fine = infer_labels_from_path(pcap_path)
                        labels_top[fid] = top
                        labels_mid[fid] = mid
                        labels_fine[fid] = fine
                        records.append(feat)            
    return records, labels_top, labels_mid, labels_fine

# 저장 함수
def save_jsonl_gz(path, data_list):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        for item in data_list:
            f.write(json.dumps(item) + "\n")

def save_label_json(path, label_dict):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        json.dump(label_dict, f)

# 데이터 분할 및 저장
def split_and_save(records, labels_top, labels_mid, labels_fine, prefix="kisti"):
    train, temp = train_test_split(records, test_size=0.2, random_state=42)
    val, test = train_test_split(temp, test_size=0.5, random_state=42)

    for name, split in zip(["train", "valid", "test"], [train, val, test]):
        save_jsonl_gz(os.path.join(output_dir, f"{prefix}_{name}.json.gz"), split)
        split_ids = {str(item["id"]) for item in split}
        save_label_json(os.path.join(output_dir, f"{prefix}_{name}_anno_top.json.gz"),
                        {k: v for k, v in labels_top.items() if k in split_ids})
        save_label_json(os.path.join(output_dir, f"{prefix}_{name}_anno_mid.json.gz"),
                        {k: v for k, v in labels_mid.items() if k in split_ids})
        save_label_json(os.path.join(output_dir, f"{prefix}_{name}_anno_fine.json.gz"),
                        {k: v for k, v in labels_fine.items() if k in split_ids})

# 실행
if __name__ == "__main__":
    all_records, anno_top, anno_mid, anno_fine = traverse_and_process_all_pcaps(dataset_root)
    split_and_save(all_records, anno_top, anno_mid, anno_fine)
