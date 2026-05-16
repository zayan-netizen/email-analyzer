import re

from email import policy
from email.parser import BytesParser

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

def parse_email(file_content):

	msg = BytesParser(policy=policy.default).parsebytes(file_content)

	body = get_email_body(msg)

	urls = extract_url(body)

	email_data = {
		"from": msg["from"],
		"to": msg["to"],
		"subject": msg["subject"],
		"date": msg["date"],
		"body": body,
		"url": urls
	}

	return email_data