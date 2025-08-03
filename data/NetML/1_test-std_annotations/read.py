import gzip
import json

with gzip.open('1_test-std_anno_fine.json.gz', 'rt', encoding='utf-8') as f:
    for i in range(5):
        print(repr(f.readline()))
        
file_path = '1_test-std_anno_fine.json.gz'

with gzip.open(file_path, 'rt', encoding='utf-8') as f:
    data = json.load(f)  # 여기서 오류 없이 잘 읽힘

print(type(data))       # <class 'dict'>
print(len(data))        # 몇 개의 키가 있는지 확인
print(list(data.items())[:5])  # 앞에서 5개만 출력