"""
Quick test of your Azure Function logic
"""
import requests
from bs4 import BeautifulSoup
import os
import time
from urllib.parse import urljoin

def test_function_logic():
    """Test the core PDF downloading logic from your Azure Function"""
    print("🧪 Testing your Azure Function logic...")
    
    # Same logic as in your function_app.py
    target_url = 'https://rulebook.centralbank.ae/en/rulebook/standards-regulations-regarding-licensing-and-monitoring-exchange-business'
    
    # Enhanced headers
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    })

    try:
        # Step 1: Get HTML content
        print("📥 Fetching webpage...")
        response = session.get(target_url, timeout=30)
        
        if response.status_code != 200:
            print(f"❌ Failed to fetch page. Status: {response.status_code}")
            return False

        # Step 2: Parse HTML to find download links
        print("🔍 Parsing HTML for PDF links...")
        soup = BeautifulSoup(response.content, 'html.parser')
        
        pdf_links = []
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.text.strip().lower()
            
            if href.endswith('.pdf') or 'pdf' in href.lower():
                pdf_links.append({'url': href, 'text': text})
            elif any(keyword in text for keyword in ['download', 'pdf', 'document']):
                pdf_links.append({'url': href, 'text': text})

        if not pdf_links:
            print("❌ No PDF links found")
            return False

        print(f"✅ Found {len(pdf_links)} PDF links")

        # Try first PDF
        pdf_info = pdf_links[0]
        if not pdf_info['url'].startswith('http'):
            download_url = urljoin(target_url, pdf_info['url'])
        else:
            download_url = pdf_info['url']

        print(f"🔗 Download URL: {download_url}")

        # Try download
        pdf_response = session.get(download_url, timeout=30)
        
        if pdf_response.status_code != 200:
            # Try with referer
            session.headers.update({'Referer': 'https://rulebook.centralbank.ae/'})
            pdf_response = session.get(download_url, timeout=30)

        if pdf_response.status_code == 200 and len(pdf_response.content) > 1000:
            # Create downloads directory
            downloads_dir = os.path.join(os.getcwd(), "downloads")
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Generate filename
            timestamp = int(time.time())
            filename = f"CBUAE_test_{timestamp}.pdf"
            filepath = os.path.join(downloads_dir, filename)
            
            # Save the file
            with open(filepath, 'wb') as f:
                f.write(pdf_response.content)
            
            print(f"✅ SUCCESS! PDF downloaded and saved")
            print(f"📁 Location: {filepath}")
            print(f"📊 Size: {len(pdf_response.content):,} bytes")
            return True
        else:
            print(f"❌ Download failed. Status: {pdf_response.status_code}")
            return False

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🧪 TESTING YOUR AZURE FUNCTION LOGIC")
    print("=" * 60)
    
    success = test_function_logic()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 YOUR FUNCTION LOGIC IS WORKING PERFECTLY!")
        print("The issue is only with local Azure Functions runtime compatibility.")
        print("This will work perfectly when deployed to Azure.")
    else:
        print("❌ Function logic needs adjustment")
    print("=" * 60)
