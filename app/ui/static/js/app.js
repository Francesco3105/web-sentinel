// Ask for confirmation before submitting forms marked with data-confirm.
// Forms marked with data-busy show that label on their button while the request runs.
document.addEventListener("submit", (event) => {
  const form = event.target;
  const message = form.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
    return;
  }
  const button = form.querySelector("button[type=submit]");
  if (form.dataset.busy && button) {
    button.dataset.label = button.textContent;
    button.textContent = form.dataset.busy;
    button.setAttribute("aria-busy", "true");
    button.disabled = true;
  }
});

// Coming back with the browser's Back button restores the page as it was left.
window.addEventListener("pageshow", (event) => {
  if (!event.persisted) return;
  document.querySelectorAll("button[aria-busy=true]").forEach((button) => {
    button.textContent = button.dataset.label;
    button.removeAttribute("aria-busy");
    button.disabled = false;
  });
});
