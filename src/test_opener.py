try:
    with open("test-file.txt", "rb") as f:
        print("Success! I can open the file.")
        print(f"Content: {f.read(10)}")
except Exception as e:
    print(f"Failed! Error: {e}")
