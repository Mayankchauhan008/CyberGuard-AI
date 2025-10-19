document.addEventListener('DOMContentLoaded', function() {
  // Add loading animation to buttons when clicked
  const buttons = document.querySelectorAll('.submit-btn');
  buttons.forEach(button => {
    button.addEventListener('click', function() {
      const originalText = this.innerHTML;
      this.innerHTML = '<div class="loading"></div> Analyzing...';
      this.disabled = true;
      
      // Re-enable after form submission (this will be overridden by page reload)
      setTimeout(() => {
        this.innerHTML = originalText;
        this.disabled = false;
      }, 2000);
    });
  });

  // Add floating animation to cards
  const cards = document.querySelectorAll('.scanner-card');
  cards.forEach((card, index) => {
    card.style.animationDelay = `${index * 0.2}s`;
  });
});
