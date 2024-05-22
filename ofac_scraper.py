import logging
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager

class OfacWebsiteScraper:
    def __init__(self):
        # Set up Chrome options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")

        # Automatically download and set up ChromeDriver
        self.service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=self.service, options=chrome_options)

    def open_website(self, url):
        self.driver.get(url)

    def wait_for_element(self, by, value, timeout=30):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )

    def click_element(self, by, value):
        element = self.driver.find_element(by, value)
        element.click()

    def get_element_text(self, by, value):
        return self.driver.find_element(by, value).text

    def get_sha256_checksum(self):
        self.open_website("https://sanctionslist.ofac.treas.gov/Home/SdnList")

        # Wait until the 'File Signatures' button with the known ID is present
        self.wait_for_element(By.ID, "accordion__heading-raa-1")

        # Click the 'File Signatures' button with the known ID
        self.click_element(By.ID, "accordion__heading-raa-1")

        # Wait for the checksums panel to be visible
        self.wait_for_element(By.ID, "accordion__panel-raa-1")
        time.sleep(3)

        # Extract the checksums content
        checksums_content = self.get_element_text(By.ID, "accordion__panel-raa-1")
        
        # Parse and return only the SHA-256 checksum
        sha256_checksum = checksums_content.split('SHA-256: ')[1].split('\n')[0]
        return sha256_checksum

    def close(self):
        self.driver.quit()

if __name__ == "__main__":
    scraper = OfacWebsiteScraper()
    try:
        sha256_checksum = scraper.get_sha256_checksum()
        print(sha256_checksum)
    finally:
        scraper.close()
