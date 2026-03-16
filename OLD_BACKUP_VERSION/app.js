document.getElementById("csvFile").addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;
        parseCSV(text);
    };
    reader.readAsText(file);
});

function parseCSV(csv) {
    const rows = csv.split("\n").slice(1);
    const tbody = document.querySelector("#resultsTable tbody");
    tbody.innerHTML = "";

    rows.forEach(row => {
        if (!row.trim()) return;

        const cols = row.split(",");
        const verdict = cols[7]?.trim() || "";

        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>${cols[0]}</td>
            <td>${cols[1]}</td>
            <td>${cols[2]}</td>
            <td>${cols[3]}</td>
            <td>${cols[6]}</td>
            <td class="${getVerdictClass(verdict)}">${verdict}</td>
        `;

        tbody.appendChild(tr);
    });
}

function getVerdictClass(verdict) {
    verdict = verdict.toLowerCase();
    if (verdict.includes("high")) return "high";
    if (verdict.includes("medium")) return "medium";
    if (verdict.includes("low")) return "low";
    if (verdict.includes("cgnat")) return "cgnat";
    return "";
}
