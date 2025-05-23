import logging
import time
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
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
        self.service = Service("/usr/bin/chromedriver")
        self.driver = webdriver.Chrome(service=self.service, options=chrome_options)

    def open_website(self, url):
        self.driver.get(url)

    def wait_for_element(self, by, value, timeout=30):
        return WebDriverWait(self.driver, timeout).until(
            EC.presence_of_element_located((by, value))
        )

    def get_element_text(self, by, value):
        return self.driver.find_element(by, value).text

    def get_sha256_checksum(self):
        MAX_RETRIES = 10
        RETRY_DELAY = 10  # seconds to wait before retrying

        for attempt in range(MAX_RETRIES):
            print(
                f"Attempting to get SHA-256 checksum (attempt {attempt + 1}/{MAX_RETRIES})..."
            )
            try:
                self.open_website("https://sanctionslist.ofac.treas.gov/Home/SdnList")
                print("Website opened")

                # Wait until the 'File Signatures' button with the known ID is present
                self.wait_for_element(By.ID, "accordion__heading-:r1:")
                print("File Signatures button found")

                # Scroll to (waiting for animation) and Click the 'File
                # Signatures' button with the known ID
                header_element = self.driver.find_element(By.ID, "accordion__heading-:r1:")
                ActionChains(self.driver).move_to_element(header_element).perform()
                time.sleep(1)
                header_element.click()
                print("File Signatures button clicked")

                # Wait for the checksums panel to be visible
                self.wait_for_element(By.ID, "accordion__panel-:r1:")
                time.sleep(3)
                print("Checksums panel found")

                # Extract the checksums content
                checksums_content = self.get_element_text(
                    By.ID, "accordion__panel-:r1:"
                )
                print("Checksums content extracted")

                # Parse and return only the SHA-256 checksum
                if "SHA-256: " not in checksums_content:
                    raise ValueError("SHA-256 checksum not found")
                sha256_checksum = checksums_content.split("SHA-256: ")[1].split("\n")[0]
                return sha256_checksum

            except TimeoutException:
                print(
                    f"Timeout occurred on attempt {attempt + 1}/{MAX_RETRIES}. Retrying in {RETRY_DELAY} seconds..."
                )
                time.sleep(RETRY_DELAY)
                if attempt == MAX_RETRIES - 1:
                    raise TimeoutException(
                        "Max retries reached. The website is not responding."
                    )

    def close(self):
        self.driver.quit()


if __name__ == "__main__":
    scraper = OfacWebsiteScraper()
    try:
        sha256_checksum = scraper.get_sha256_checksum()
        print(sha256_checksum)
    finally:
        scraper.close()
