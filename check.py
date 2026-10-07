import os

files = [
    "models/sqli_model.pkl",
    "datasets/sqli.csv"
]

for file in files:
    print("\nFILE:", file)

    if not os.path.exists(file):
        print("❌ NOT FOUND")
        continue

    with open(file, "rb") as f:
        data = f.read(20)

    print("First bytes:", data)