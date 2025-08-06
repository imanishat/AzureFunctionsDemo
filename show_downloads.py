import os

def show_downloaded_files():
    downloads_dir = os.path.join(os.getcwd(), "downloads")
    
    if not os.path.exists(downloads_dir):
        print("❌ Downloads folder not found")
        return
        
    files = [f for f in os.listdir(downloads_dir) if f.endswith('.pdf')]
    
    if not files:
        print("❌ No PDF files found in downloads folder")
        return
        
    print("📁 Downloaded PDF Files:")
    print("=" * 50)
    
    for file in files:
        filepath = os.path.join(downloads_dir, file)
        size = os.path.getsize(filepath)
        print(f"📄 {file}")
        print(f"   Size: {size:,} bytes ({size/1024/1024:.1f} MB)")
        print(f"   Path: {filepath}")
        print()
        
    print(f"✅ Total: {len(files)} PDF file(s) downloaded")

if __name__ == "__main__":
    show_downloaded_files()
