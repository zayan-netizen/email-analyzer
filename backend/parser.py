import re

from email import policy
from email.parser import BytesParser

from urllib.parse import urlparse
import ipaddress

def extract_url(text):

	url_pattern = 'https?://[^\s]+'

	urls = re.findall(url_pattern, text)

	return urls

def get_email_body(msg):

	if msg.is_multipart():
		for part in msg.walk():
			content_type = part.get_content_type()
			if content_type == "text/plain":
				try:
					return part.get_content()
				except Exception: 
					return "Could not extract body"
	else:
		return msg.get_content()

	return "No body found"

def analyse_urls(url):
	
	findings = []

	parsed = urlparse(url)

	domain = parsed.netloc

	suspicious_keywords = [
							"login",
							"verify",
							"secure",
							"account",
							"update",
							"bank"
						]

	shorteners = [
					"bit.ly",
					"tinyurl.com",
					"t.co"
				]

	for shortener in shorteners:
		if shortener in domain:
			findings.append("Uses URL shortener")

	for keyword in suspicious_keywords:
		if keyword in url.lower():
			findings.append(f"Contains malicious keyword {keyword}")

	try:
		ipaddress.ip_address(domain)
		findings.append("Uses IP address instead of domain")
	except:
		pass

	return findings

def parse_email(file_content):

	msg = BytesParser(policy=policy.default).parsebytes(file_content)

	body = get_email_body(msg)

	urls = extract_url(body)

	url_analysis = []

	for url in urls:

		findings = analyse_urls(url)

		url_analysis.append({
			"url": url,
			"findings": findings
			})

	email_data = {
		"from": msg["from"],
		"to": msg["to"],
		"subject": msg["subject"],
		"date": msg["date"],
		"body": body,
		"url_analysis": url_analysis
	}

	return email_data
