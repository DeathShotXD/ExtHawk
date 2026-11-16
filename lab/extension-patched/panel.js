// Internal extension page, not exposed through web_accessible_resources.
// Input is rendered as text, never as markup.
const note = document.getElementById("note");
note.textContent = decodeURIComponent(location.hash.slice(1));
