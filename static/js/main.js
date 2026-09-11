// Small, dependency-free front-end behavior for the laboratory storefront.
document.querySelectorAll('.flash').forEach((message) => {
  setTimeout(() => message.remove(), 5000);
});
