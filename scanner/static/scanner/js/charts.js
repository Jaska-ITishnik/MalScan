(function(){
  const score = window.__SCAN_SCORE__;
  if (typeof score !== "number") return;
  const el = document.getElementById("riskChart");
  if (!el) return;

  const benign = Math.max(0, 100 - score);
  new Chart(el, {
    type: "doughnut",
    data: {
      labels: ["Malicious probability", "Remaining"],
      datasets: [{
        data: [score, benign],
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: true } }
    }
  });
})(); 
