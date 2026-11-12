'use strict';
document.querySelectorAll('[data-copy]').forEach(button => {
  button.addEventListener('click', async () => {
    const field = document.getElementById(button.dataset.copy);
    const status = document.getElementById('copy-status');
    try {
      await navigator.clipboard.writeText(field.value);
      status.textContent = 'Скопировано. Вставь в VPN-приложение.';
    } catch (_) {
      field.focus();
      field.select();
      const copied = document.execCommand('copy');
      status.textContent = copied ? 'Скопировано.' : 'Текст выделен: скопируй его вручную.';
    }
    const old = button.textContent;
    button.textContent = 'Готово';
    setTimeout(() => { button.textContent = old; }, 1800);
  });
});
