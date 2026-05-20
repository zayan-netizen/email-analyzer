def calculate_risk_score(url_analysis, header_findings, attachment_findings):

	score = 0

	for item in url_analysis:

		findings = item["findings"]

		for finding in findings:

			if "URL shortener" in finding:
				score += 20

			elif "IP address" in finding:
				score += 30

			elif "suspicious keyword" in finding:
				score += 10

	for finding in header_findings:

		if "Free Email Provider" in finding.lower():
			score += 15

		elif "Reply-to differs" in finding.lower():
			score += 25

		elif "Suspicious domain keyword" in finding.lower():
			score += 20

	for finding in attachment_findings:

		if "Dangerous attachment type" in finding:
			score += 40

		elif "Macro-enabled" in finding:
			score += 35

		elif "double-extension" in finding:
			score += 30


	return score

def classify_risk(score):

	if score >= 70:
		return "DANGEROUS"

	elif score >= 30:
		return "SUSPICIOUS"

	return "SAFE"