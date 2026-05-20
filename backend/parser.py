import re

from email import policy
from email.parser import BytesParser

from urllib.parse import urlparse
import ipaddress

from email.utils import parseaddr

def extract_url(text):

	url_pattern = r'https?://[^\s]+'

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

def analyse_header(msg):

	findings = []

	sender = msg["from"]
	reply_to = msg["reply-to"]

	free_email_domains = [
							"google.com",
							"yahoo.com",
							"outlook.com",
							"gmail.com"
						]

	suspicious_keywords = [
							"support",
							"security",
							"verify",
							"update"
							]

	sender_email = parseaddr(sender)[1]

	sender_domain = ""

	if "@" in sender_email:
		sender_domain = sender_email.split("@")[1]

	if sender_domain in free_email_domains:

		findings.append("Uses Free Email Provider")

	for keyword in suspicious_keywords:
		if keyword in sender_email:
			findings.append(f"Suspicious domain keyword: {keyword}")

	if reply_to:

		reply_email = parseaddr(reply_to)[1]

		if sender_email != reply_email:

			findings.append("Reply-to differs from sender-email")

	return findings

def parse_email(file_content):

	msg = BytesParser(policy=policy.default).parsebytes(file_content)

	body = get_email_body(msg)

	urls = extract_url(body)

	header_findings = analyse_header(msg)

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
		"header_findings": header_findings,
		"url_analysis": url_analysis

	}

	return email_data

