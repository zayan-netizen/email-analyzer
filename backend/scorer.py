def calculate_risk_score(url_analysis):

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

		return score

def classify_risk(score):

	if score >= 70:
		return "DANGEROUS"

	elif score >= 30:
		return "SUSPICIOUS"

	return "SAFE"