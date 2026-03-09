scanForm.addEventListener("submit", async function(e) {
    e.preventDefault();

    if (!realFileBtn.files.length) {
        alert("Please select a file first.");
        return;
    }

    const spinner = document.getElementById("spinner");
    const progressBar = document.getElementById("progress-bar");

    spinner.style.display = "block";
    progressBar.style.width = "0%";

    const formData = new FormData();
    formData.append("file", realFileBtn.files[0]);

    const response = await fetch("/scan", {
        method: "POST",
        body: formData
    });

    const data = await response.json();

    table.innerHTML = `
        <tr>
            <th>S.No</th>
            <th>IP</th>
            <th>AbuseIP %</th>
            <th>VT Engine %</th>
        </tr>
    `;

    let total = data.length;
    let count = 0;

    data.forEach(row => {
        count++;
        let riskClass = "";

        if (row.vt !== "ERROR") {
            let vtValue = parseFloat(row.vt);

            if (vtValue > 50) {
                riskClass = "high-risk";
            }
        }

        table.innerHTML += `
            <tr>
                <td>${row.serial}</td>
                <td>${row.ip}</td>
                <td>${row.abuse}</td>
                <td class="${riskClass}">${row.vt}</td>
            </tr>
        `;

        let percent = (count / total) * 100;
        progressBar.style.width = percent + "%";
    });

    spinner.style.display = "none";
});