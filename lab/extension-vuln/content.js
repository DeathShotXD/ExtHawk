(() => {
  const render = (html) => {
    let box = document.getElementById("hawk-notes");
    if (!box) {
      box = document.createElement("div");
      box.id = "hawk-notes";
      box.style.cssText =
        "position:fixed;right:16px;bottom:16px;max-width:320px;padding:12px;" +
        "background:#111;color:#eee;border:1px solid #444;border-radius:8px;" +
        "font:13px system-ui;z-index:2147483647";
      document.body.appendChild(box);
    }
    box.innerHTML = html;
  };

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.type !== "hawk-render") return;
    render(data.html);
  });
})();
