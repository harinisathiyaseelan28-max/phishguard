const $ = (id) => document.getElementById(id);
const COLORS = { PHISHING: "#ef4444", SUSPICIOUS: "#f59e0b", SAFE: "#22c55e" };

function fill(list, items, emptyText) {
  list.replaceChildren();
  if (!items.length) {
    const li = document.createElement("li");
    li.textContent = emptyText;
    list.appendChild(li);
    return;
  }
  items.forEach((t) => {
    const li = document.createElement("li");
    li.textContent = t; // textContent => no HTML injection
    list.appendChild(li);
  });
}

async function analyze() {
  const content = $("input").value.trim();
  if (!content) { alert("Please paste something to analyze."); return; }
  $("analyze").disabled = true;
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    const d = await res.json();
    if (!res.ok) { alert(d.error || "Error"); return; }

    $("result").classList.remove("hidden");
    const badge = $("badge");
    badge.textContent = d.verdict;
    badge.className = "badge " + d.verdict;
    $("bar").style.width = d.risk_score + "%";
    $("bar").style.background = COLORS[d.verdict];
    $("score").textContent = "Risk score: " + d.risk_score + " / 100";
    $("advice").textContent = d.advice;
    fill($("reasons"), d.reasons, "No specific red flags detected.");
    fill($("urls"), d.urls.map((u) => `${u.url} → ${u.verdict} (${Math.round(u.probability * 100)}%)`),
         "No links found.");
  } catch (e) {
    alert("Could not reach the server: " + e);
  } finally {
    $("analyze").disabled = false;
  }
}

$("analyze").addEventListener("click", analyze);
$("clear").addEventListener("click", () => { $("input").value = ""; $("result").classList.add("hidden"); });
document.querySelectorAll(".samples a").forEach((a) =>
  a.addEventListener("click", (e) => { e.preventDefault(); $("input").value = a.dataset.s; analyze(); }));

fetch("/api/metrics").then((r) => r.ok ? r.json() : null).then((m) => {
  if (!m) return;
  $("metrics").textContent =
    `Model performance on held-out test data — Text model: accuracy ${(m.text_model.accuracy * 100).toFixed(1)}%, F1 ${m.text_model.f1}. ` +
    `URL model: accuracy ${(m.url_model.accuracy * 100).toFixed(1)}%, F1 ${m.url_model.f1}.`;
});
