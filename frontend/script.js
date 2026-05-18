const button = document.getElementById("parse-file");

button.addEventListener("click", async () => {

	const fileInput = document.getElementById("emailFile");

	const file = fileInput.files[0];

	if(!file){
		alert("Please select a file!");
		return;
	}

	const formData = new FormData();

	formData.append("file", file);

	const response = await fetch("http://127.0.0.1:8000/analyze", {
		method: 'POST',
		body: formData
	});

	const data = await response.json();

	console.log(data);

	displayResults(data);
});

function displayResults(data){

	const resultDiv = document.getElementById("results")

	let riskClass = "";

	if(data.classification == "SAFE"){
		riskClass = "SAFE";
	}
	else if(data.classification == "SUSPICIOUS"){
		riskClass = "SUSPICIOUS";
	} else {
		riskClass = "DANGEROUS"
	}

	html = `
		<h2 class="${riskClass}">
			${data.classification}
		</h2>

		<p><strong>Risk Score:</strong>${data.risk_score}</p>

		<p><strong>From:</strong>${data.from}</p>

		<p><strong>Subject:</strong>${data.subject}</p>

		<h3>Detected URLS:</h3>
	`;

	data.url_analysis.forEach(item => {

		html += `
			<div class="url-card">

				<p>
					<strong>URL:</strong>
					${item.url}
				</p>

			<ul>
			`;

		item.findings.forEach(finding => {

			html += `
				<li>${finding}</li>
			`;
		});

		html += `
				</ul>

			</div>
			`;
	});

	resultDiv.innerHTML = html;
}
