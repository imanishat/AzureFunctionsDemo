import requests
from bs4 import BeautifulSoup
import tempfile
import os
from urllib.parse import urljoin
import time

def download_pdf_locally():
    """Enhanced PDF downloader that tries multiple approaches"""
    print("🔍 Starting enhanced PDF download process...")

    # URL to scrape
    target_url = 'https://rulebook.centralbank.ae/en/rulebook/standards-regulations-regarding-licensing-and-monitoring-exchange-business'

    # Enhanced headers to better mimic a real browser
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Cache-Control': 'max-age=0'
    })

    try:
        # Step 1: Get HTML content
        print("📥 Fetching webpage...")
        response = session.get(target_url, timeout=30)
        print(f"✅ Response status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"❌ Failed to fetch page. Status code: {response.status_code}")
            return False

        # Step 2: Parse HTML to find download link
        print("🔍 Parsing HTML for PDF links...")
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Look for PDF links more comprehensively
        pdf_links = []
        
        # Method 1: Look for direct PDF links
        for a in soup.find_all('a', href=True):
            href = a['href']
            text = a.text.strip().lower()
            
            if href.endswith('.pdf') or 'pdf' in href.lower():
                pdf_links.append({
                    'url': href,
                    'text': text,
                    'method': 'direct_pdf_link'
                })
            elif any(keyword in text for keyword in ['download', 'pdf', 'document']):
                pdf_links.append({
                    'url': href,
                    'text': text,
                    'method': 'download_text'
                })

        # Method 2: Look for embedded PDFs or iframe sources
        for iframe in soup.find_all('iframe', src=True):
            if 'pdf' in iframe['src'].lower():
                pdf_links.append({
                    'url': iframe['src'],
                    'text': 'embedded_pdf',
                    'method': 'iframe'
                })

        print(f"📋 Found {len(pdf_links)} potential PDF links:")
        for i, link in enumerate(pdf_links):
            print(f"  {i+1}. {link['text'][:50]} -> {link['url']}")

        if not pdf_links:
            print("❌ No PDF links found")
            return False

        # Try each PDF link
        for i, pdf_info in enumerate(pdf_links):
            print(f"\n🔄 Trying PDF link {i+1}: {pdf_info['url']}")
            
            # Handle relative URLs
            if not pdf_info['url'].startswith('http'):
                download_url = urljoin(target_url, pdf_info['url'])
            else:
                download_url = pdf_info['url']
            
            print(f"🌐 Full URL: {download_url}")

            # Try multiple download approaches
            success = try_download_approaches(session, download_url, i+1)
            if success:
                return True

        print("❌ All download attempts failed")
        return False

    except Exception as e:
        print(f"❌ Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def try_download_approaches(session, url, link_number):
    """Try different approaches to download the PDF"""
    
    approaches = [
        ("Direct download", lambda: direct_download(session, url)),
        ("With referer header", lambda: download_with_referer(session, url)),
        ("Selenium approach", lambda: selenium_download(url)),
    ]
    
    for approach_name, approach_func in approaches:
        try:
            print(f"  🔧 Trying: {approach_name}")
            result = approach_func()
            if result:
                print(f"  ✅ Success with {approach_name}!")
                return True
            else:
                print(f"  ❌ Failed with {approach_name}")
        except Exception as e:
            print(f"  ❌ Error with {approach_name}: {str(e)}")
    
    return False

def direct_download(session, url):
    """Direct download approach"""
    response = session.get(url, timeout=30)
    if response.status_code == 200 and 'application/pdf' in response.headers.get('content-type', ''):
        return save_pdf(response.content, "direct_download")
    return False

def download_with_referer(session, url):
    """Download with referer header"""
    session.headers.update({
        'Referer': 'https://rulebook.centralbank.ae/',
    })
    response = session.get(url, timeout=30)
    if response.status_code == 200:
        return save_pdf(response.content, "with_referer")
    return False

def selenium_download(url):
    """Selenium-based download (if available)"""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(options=options)
        driver.get(url)
        
        # This would require more complex handling
        # For now, just return False
        driver.quit()
        return False
    except ImportError:
        print("    Selenium not available")
        return False

def save_pdf(content, method):
    """Save PDF content to local file"""
    try:
        # Create downloads directory in current folder
        downloads_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = int(time.time())
        filename = f"CBUAE_rulebook_{method}_{timestamp}.pdf"
        filepath = os.path.join(downloads_dir, filename)
        
        # Check if content looks like a PDF
        if len(content) < 1000:
            print(f"    Content too small ({len(content)} bytes), likely not a PDF")
            return False
            
        if not content.startswith(b'%PDF'):
            print(f"    Content doesn't start with PDF header")
            return False
        
        # Save the file
        with open(filepath, 'wb') as f:
            f.write(content)
        
        print(f"  ✅ PDF saved successfully!")
        print(f"  📁 Location: {filepath}")
        print(f"  📊 Size: {len(content):,} bytes")
        
        return True
        
    except Exception as e:
        print(f"    Error saving file: {str(e)}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 ENHANCED PDF DOWNLOADER")
    print("=" * 60)
    
    success = download_pdf_locally()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 DOWNLOAD COMPLETED SUCCESSFULLY!")
        print("Check the 'downloads' folder in your project directory.")
    else:
        print("😞 DOWNLOAD FAILED")
        print("The website may have strong protection against automated downloads.")
    print("=" * 60)
