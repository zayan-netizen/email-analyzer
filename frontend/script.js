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

	alert(`
		File: ${data.filename}
		Size: ${data.size_in_bytes} bytes
	`);
})
