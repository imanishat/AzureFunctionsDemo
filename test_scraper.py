import requests
from bs4 import BeautifulSoup
import tempfile

def test_pdf_scraper():
    """Test the PDF scraper functionality directly"""
    print("Testing PDF scraper function...")

    # URL to scrape
    target_url = 'https://rulebook.centralbank.ae/en/rulebook/standards-regulations-regarding-licensing-and-monitoring-exchange-business'

    # Add headers to mimic a real browser
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    try:
        # Step 1: Get HTML content
        print("Fetching webpage...")
        response = requests.get(target_url, headers=headers, timeout=30)
        print(f"Response status code: {response.status_code}")
        
        if response.status_code != 200:
            print(f"Failed to fetch page. Status code: {response.status_code}")
            print(f"Response text (first 500 chars): {response.text[:500]}")
            return

        # Step 2: Parse HTML to find download link
        print("Parsing HTML for PDF links...")
        soup = BeautifulSoup(response.content, 'html.parser')
        download_link = None

        # This depends on the website structure – here's a generic example:
        for a in soup.find_all('a', href=True):
            if 'download' in a.text.lower() or a['href'].endswith('.pdf'):
                download_link = a['href']
                print(f"Found potential PDF link: {download_link}")
                break

        if not download_link:
            print("No download link found on the page")
            # Let's see what links are available
            print("Available links on the page:")
            for i, a in enumerate(soup.find_all('a', href=True)[:10]):  # Show first 10 links
                print(f"  {i+1}. {a.text.strip()[:50]} -> {a['href']}")
            return

        # Step 3: Handle relative URLs
        if not download_link.startswith('http'):
            from urllib.parse import urljoin
            download_link = urljoin(target_url, download_link)

        print(f"Full download URL: {download_link}")

        # Step 4: Download the PDF content
        print("Downloading PDF...")
        pdf_response = requests.get(download_link)
        if pdf_response.status_code != 200:
            print(f"Failed to download PDF. Status code: {pdf_response.status_code}")
            return

        # Use temporary directory instead of /tmp for Windows compatibility
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_file:
            temp_file.write(pdf_response.content)
            temp_file_path = temp_file.name

        print(f"✅ PDF downloaded successfully!")
        print(f"📁 Saved to: {temp_file_path}")
        print(f"📊 File size: {len(pdf_response.content)} bytes")

    except Exception as e:
        print(f"❌ Error occurred: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_pdf_scraper()
