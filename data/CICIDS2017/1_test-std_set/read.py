import gzip
import json

file_path = '1_test-std_set.json.gz'

data = []
with gzip.open(file_path, 'rt', encoding='utf-8') as f:
    for line in f:
        try:
            item = json.loads(line)
            data.append(item)
        except json.JSONDecodeError as e:
            print(f"Error decoding line: {e}")

print(f"Loaded {len(data)} records")
print(data[0])        # 첫 번째 레코드
